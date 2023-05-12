/*
Author: Aravind Prabhakar
Version: v1.0
Description: This is a script to program flowspec routes to a juniper router using pRPD
*/

package main

import (
	"context"
	"fmt"
	auth "jnx/jet/auth"
	jnx "jnx/jet/common"
	rtg "jnx/jet/routing"

	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	JET_HOST           = "127.0.0.1"
	JET_PORT           = "50051"
	JET_USER           = "root"
	JET_PASSWD         = "Embe1mpls"
	TIMEOUT            = 30
	ACTION             = "DISCARD" //DISCARD or REDIRECT_TO_VRF
	REDIRECT_IP        = "10.1.1.1"
	REDIRECT_COMMUNITY = "target:13979:999"
	COMMUNITY          = "13979:999"
	PNH_IP             = "10.1.1.1"
)

// initiate JET session with junos
type Session struct {
	// jetConn holds the gRPC connection made to cRPD
	jetConn *grpc.ClientConn

	//pRPD flowspec to handle gRPC
	bgpClient rtg.BgpClient

	// cliContext is used for gRPC requests to RIB service.
	cliContext context.Context
}

var junos Session

func connectJET(addr string) error {
	if junos.jetConn != nil {
		return nil
	}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(time.Duration(TIMEOUT)*time.Second))
	if err != nil {
		fmt.Println("did not connect: %s", err)
	}
	junos.jetConn = conn
	clientId := "flowspec"
	md := metadata.Pairs("client-id", clientId)
	login := auth.NewAuthenticationClient(conn)
	loginReq := &auth.LoginRequest{
		Username: JET_USER,
		Password: JET_PASSWD,
		ClientId: clientId,
	}
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	if reply, err := login.Login(junos.cliContext, loginReq); err != nil {
		fmt.Println("Error authenticating..\n")
	} else if reply.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("Failed to authenticate\n")
	}
	fmt.Println("connected to grpc")
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	junos.bgpClient = rtg.NewBgpClient(conn)
	return nil
}

// delete a flowspec route from inetflow.0 table
func delFlow(src_ip string, dst_ip string, src_port uint32, dst_port uint32) {
	dstIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: dst_ip}}
	srcIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: src_ip}}

	var srcPortList []*jnx.NumericRange
	srcPort := &jnx.NumericRange{Min: src_port, Max: src_port}
	srcPortList = append(srcPortList, srcPort)
	srcPorts := &jnx.NumericRangeList{RangeList: srcPortList}

	var dstPortList []*jnx.NumericRange
	dstPort := &jnx.NumericRange{Min: dst_port, Max: dst_port}
	dstPortList = append(dstPortList, dstPort)
	dstPorts := &jnx.NumericRangeList{RangeList: dstPortList}

	// flowspec match conditions
	flowMatch := &rtg.FlowspecAddress{
		Destination:     dstIP,
		DestPrefixLen:   32,
		Source:          srcIP,
		SourcePrefixLen: 32,
		SrcPorts:        srcPorts,
		DestPorts:       dstPorts,
		//IpProtocols:
	}
	flowRt := &rtg.RoutePrefix{
		RoutePrefixAf: &rtg.RoutePrefix_InetFlowspec{InetFlowspec: flowMatch},
	}
	// communities defn
	var communitySlice []*rtg.Community
	communities := &rtg.Community{Community: COMMUNITY}
	communitySlice = append(communitySlice, communities)
	communitySlices := &rtg.Communities{Communities: communitySlice}

	matchRt := &rtg.RouteMatch{
		DestPrefix:    flowRt,
		DestPrefixLen: 32,
		Table:         &rtg.RouteTable{RouteTableFormat: &rtg.RouteTable_Name{Name: &rtg.RouteTableName{Name: "inetflow.0"}}},
		Protocol:      rtg.RouteProtoType_PROTO_BGP_STATIC,
		Cookie:        999, //hardcoded
		Communities:   communitySlices,
	}

	var matchRtSlice []*rtg.RouteMatch
	matchRtSlice = append(matchRtSlice, matchRt)
	delRequest := &rtg.RouteDeleteRequest{OrLonger: false, Routes: matchRtSlice}
	resp, err := junos.bgpClient.RouteDelete(junos.cliContext, delRequest)
	if err != nil {
		fmt.Println("Failed to add flowspec route")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

// Add a flowspec route based on received flow with 5 tuple information with redirect-to-vrf or reject action
func addFlow(src_ip string, dst_ip string, src_port uint32, dst_port uint32, action string) {
	// save name for deleting purposes
	fmt.Println(src_ip, dst_ip)
	dstIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: dst_ip}}
	srcIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: src_ip}}

	var srcPortList []*jnx.NumericRange
	srcPort := &jnx.NumericRange{Min: src_port, Max: src_port}
	srcPortList = append(srcPortList, srcPort)
	srcPorts := &jnx.NumericRangeList{RangeList: srcPortList}

	var dstPortList []*jnx.NumericRange
	dstPort := &jnx.NumericRange{Min: dst_port, Max: dst_port}
	dstPortList = append(dstPortList, dstPort)
	dstPorts := &jnx.NumericRangeList{RangeList: dstPortList}

	// flowspec match conditions
	flowMatch := &rtg.FlowspecAddress{
		Destination:     dstIP,
		DestPrefixLen:   32,
		Source:          srcIP,
		SourcePrefixLen: 32,
		SrcPorts:        srcPorts,
		DestPorts:       dstPorts,
		//IpProtocols:
	}
	flowRt := &rtg.RoutePrefix{
		RoutePrefixAf: &rtg.RoutePrefix_InetFlowspec{InetFlowspec: flowMatch},
	}
	// communities defn
	var communitySlice []*rtg.Community
	communities := &rtg.Community{Community: COMMUNITY}
	communitySlice = append(communitySlice, communities)
	communitySlices := &rtg.Communities{Communities: communitySlice}

	key := &rtg.RouteMatch{
		DestPrefix:    flowRt,
		DestPrefixLen: 32,
		Table:         &rtg.RouteTable{RouteTableFormat: &rtg.RouteTable_Name{Name: &rtg.RouteTableName{Name: "inetflow.0"}}},
		Protocol:      rtg.RouteProtoType_PROTO_BGP_STATIC,
		Cookie:        999, //hardcoded
		Communities:   communitySlices,
	}
	var rtentrySlice []*rtg.RouteEntry
	var flowspecRtData *rtg.FlowspecRouteData
	// if action= redirect to vrf
	if action == "REDIRECT_TO_VRF" {
		flowspecRtData = &rtg.FlowspecRouteData{
			RedirectInstRtComm: REDIRECT_COMMUNITY,
		}
	} else if action == "DISCARD" {
		flowspecRtData = &rtg.FlowspecRouteData{
			Discard: true,
		}
	}

	var nhSlice []*jnx.IpAddress
	nhIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: PNH_IP}}
	nhSlice = append(nhSlice, nhIP)
	rtentry := &rtg.RouteEntry{
		Key: key,
		//RoutePreference: UInt32Value(10),
		//LocalPreference: 1000,
		ProtocolNexthops: nhSlice,
		AddrFamilyData:   &rtg.AddressFamilySpecificData{RouteDataAf: &rtg.AddressFamilySpecificData_FlowspecData{FlowspecData: flowspecRtData}},
		RouteFlags:       &rtg.RouteFlags{UseNexthopFictitious: true},
	}
	rtentrySlice = append(rtentrySlice, rtentry)
	updrequest := &rtg.RouteUpdateRequest{
		Routes: rtentrySlice,
	}
	fmt.Println(updrequest)
	resp, err := junos.bgpClient.RouteAdd(junos.cliContext, updrequest)
	if err != nil {
		fmt.Println("Failed to add flowspec route")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

// BGP initialization
func BgpInit(bgpconn rtg.BgpClient) error {
	initRequest := &rtg.InitializeRequest{}
	resp, err := junos.bgpClient.Initialize(junos.cliContext, initRequest)
	if err != nil {
		fmt.Println("Failed to initialize BGP session")
	} else {
		fmt.Println("successfully initialized", resp)
	}
	return err
}

func main() {
	//establish connection to  MX over gRPC channel
	connectJET(JET_HOST + ":" + JET_PORT)
	BgpInit(junos.bgpClient)
	fmt.Println("finished initialization")
	//addFlow("1.1.1.1", "2.2.2.2", 1000, 2000, ACTION)
	delFlow("1.1.1.1", "2.2.2.2", 1000, 2000)
}
