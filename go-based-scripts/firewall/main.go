/*
Author: Aravind Prabhakar
Version: v1.0
Description: Flow offloader on a service chained topology. This app
will listen to syslog session Inits and closes from vSRX and offload the
flow on to MX
*/

package main

import (
	"context"
	"fmt"
	"hash/fnv"
	auth "jnx/jet/auth"
	jnx "jnx/jet/common"
	fw "jnx/jet/firewall"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	TYPE                   = "udp" //protocol type
	SESS_CREATE            = "RT_FLOW_SESSION_CREATE"
	SESS_CLOSE             = "RT_FLOW_SESSION_CLOSE"
	VALID_SESS_TIME        = 10
	TIMEOUT                = 30
	INDEX                  = 0
	ROUTE_TABLE            = "SERVICE.inet.0"
	SERVICE_FILTER         = "SERVICE"
	SERVICE_FILTER_REVERSE = "SERVICE-REVERSE"
)

// session values which would be stored in maps
type sessionValues struct {
	source_ip   string
	source_port string
	dest_ip     string
	dest_port   string
	//protocol string;
	session_time string
}

// initiate JET session with junos
type Session struct {
	// jetConn holds the gRPC connection made to cRPD
	jetConn *grpc.ClientConn

	// ribClient is the handle to send gRPC requests JUNOS PRPD RIB service.
	cliClient fw.FirewallClient

	// cliContext is used for gRPC requests to RIB service.
	cliContext context.Context
}

var junos Session

func connectJET(addr string, juser string, jpass string) error {
	if junos.jetConn != nil {
		return nil
	}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(time.Duration(TIMEOUT)*time.Second))
	if err != nil {
		fmt.Println("did not connect: %s", err)
	}
	junos.jetConn = conn
	clientId := "trafficoffload"
	md := metadata.Pairs("client-id", clientId)
	login := auth.NewLoginClient(conn)
	loginReq := &auth.LoginRequest{
		UserName: juser,
		Password: jpass,
		ClientId: clientId,
	}
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	if _, err := login.LoginCheck(junos.cliContext, loginReq); err != nil {
		fmt.Println("Error authenticating..\n")
	}
	fmt.Println("connected to grpc")
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	junos.cliClient = fw.NewFirewallClient(conn)
	return nil
}

// remove UTF-8 character
func RemoveLastChar(str string) string {
	for len(str) > 0 {
		_, size := utf8.DecodeLastRuneInString(str)
		return str[:len(str)-size]
	}
	return str
}

func RemoveFirstChar(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}

// generate Hash
func HashString(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	s := strconv.FormatUint(uint64(h.Sum32()), 10)
	return s
}

// program default accept term so that it can fall back to cli filter
func programDefaultTerm(filtername string) {
	cntName := "COUNT-JET-ACCEPT-ALL"
	Action := &fw.FilterTermInetAction{
		ActionsNt: &fw.FilterTermInetNonTerminatingAction{Count: &fw.ActionCounter{CounterName: cntName}},
		ActionT:   &fw.FilterTermInetTerminatingAction{TerminatingAction: &fw.FilterTermInetTerminatingAction_Accept{Accept: true}},
	}
	Adj := &fw.FilterAdjacency{Type: fw.FilterAdjacencyType_TERM_AFTER, TermName: "(null)"}
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterTerm{
		FilterTerm: &fw.FilterTerm_InetTerm{
			InetTerm: &fw.FilterInetTerm{
				TermName:  "JET-ACCEPT-ALL",
				TermOp:    fw.FilterTermOperation_TERM_OPERATION_ADD,
				Adjacency: Adj,
				Actions:   Action,
			},
		},
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	addreq := &fw.FilterAddRequest{
		Name:      filtername,
		Type:      fw.FilterTypes_TYPE_CLASSIC,
		Family:    fw.FilterFamilies_FAMILY_INET,
		TermsList: filterTermSlice,
	}
	fmt.Println(addreq)
	resp, err := junos.cliClient.FilterAdd(junos.cliContext, addreq)
	if err != nil {
		fmt.Println("Failed to program jet-offload default-term")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program jet-offload default-term")
	} else {
		fmt.Println("successfully programmed jet-offload default-term", resp)
	}
}

// program flow to MX as JET filter
func addFlow(filtername string, name string, src_ip string, dst_ip string, src_port string, dst_port string) {
	idstport, _ := strconv.Atoi(dst_port)
	isrcport, _ := strconv.Atoi(src_port)
	udstport := uint32(idstport)
	usrcport := uint32(isrcport)
	dstAddr := &fw.MatchIpAddress{
		Addr: &jnx.IpAddress{
			AddrFormat: &jnx.IpAddress_AddrString{
				AddrString: dst_ip,
			},
		},
		PrefixLength: 32,
		Operation:    fw.MatchOperation_OP_EQUAL,
	}
	srcAddr := &fw.MatchIpAddress{
		Addr: &jnx.IpAddress{
			AddrFormat: &jnx.IpAddress_AddrString{
				AddrString: src_ip,
			},
		},
		PrefixLength: 32,
		Operation:    fw.MatchOperation_OP_EQUAL,
	}
	dstPort := &fw.MatchPort{
		Min:       udstport,
		Max:       udstport,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	srcPort := &fw.MatchPort{
		Min:       usrcport,
		Max:       usrcport,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	var dstAddrSlice []*fw.MatchIpAddress
	var srcAddrSlice []*fw.MatchIpAddress
	var dstPortSlice []*fw.MatchPort
	var srcPortSlice []*fw.MatchPort
	dstAddrSlice = append(dstAddrSlice, dstAddr)
	dstPortSlice = append(dstPortSlice, dstPort)
	srcAddrSlice = append(srcAddrSlice, srcAddr)
	srcPortSlice = append(srcPortSlice, srcPort)
	Match := &fw.FilterTermMatchInet{
		//To do: Add protocol if needed
		Ipv4DstAddrs: dstAddrSlice,
		Ipv4SrcAddrs: srcAddrSlice,
		DstPorts:     dstPortSlice,
		SrcPorts:     srcPortSlice,
	}
	cntName := "COUNT-" + name
	Action := &fw.FilterTermInetAction{
		ActionsNt: &fw.FilterTermInetNonTerminatingAction{Count: &fw.ActionCounter{CounterName: cntName}},
		ActionT:   &fw.FilterTermInetTerminatingAction{TerminatingAction: &fw.FilterTermInetTerminatingAction_Accept{Accept: true}},
	}
	Adj := &fw.FilterAdjacency{Type: fw.FilterAdjacencyType_TERM_AFTER, TermName: "JET-ACCEPT-ALL"} // JET-ACCEPT-ALL will be placed after definining term
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterTerm{
		FilterTerm: &fw.FilterTerm_InetTerm{
			InetTerm: &fw.FilterInetTerm{
				TermName:  "OFFLOAD_" + name,
				TermOp:    fw.FilterTermOperation_TERM_OPERATION_ADD,
				Adjacency: Adj,
				Matches:   Match,
				Actions:   Action,
			},
		},
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	addreq := &fw.FilterModifyRequest{
		Name:      filtername,
		Type:      fw.FilterTypes_TYPE_CLASSIC,
		Family:    fw.FilterFamilies_FAMILY_INET,
		TermsList: filterTermSlice,
	}
	fmt.Println(addreq)
	resp, err := junos.cliClient.FilterModify(junos.cliContext, addreq)
	if err != nil {
		fmt.Println("Failed to program jet-offload filter")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program jet-offload filter")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

func main() {
	parser := argparse.NewParser("Required-args", "\n============\ntraffic-offloader\n============")
	fmt.Println("connected to host ...")
	jip := parser.String("J", "jetip", &argparse.Options{Required: true, Help: "Jet host IP "})
	jport := parser.String("P", "jetport", &argparse.Options{Required: true, Help: "Jet host port"})
	juser := parser.String("u", "user", &argparse.Options{Required: true, Help: "user name for jet host"})
	jpass := parser.String("w", "password", &argparse.Options{Required: false, Help: "password for jet host"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	} else {
		if *jpass == "" {
			log.Print("Enter Password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Err: %v\n", err)
			}
			*jpass = string(bytePassword)
		}
		for {
			//establish connection to  MX over gRPC channel
			connectJET(*jip+":"+*jport, *juser, *jpass)

			//program default accept term to fail over to cli filter for unmatched packets. Pass filtername name
			programDefaultTerm("FLOW_OFFLOAD")
			addFlow("FLOW_OFFLOAD", "term-1", "3.3.3.3", "4.4.4.4", "44000", "45000")
		}
	}
}
