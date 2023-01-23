"""
Author: Aravind Prabhakar
Description: Firewall filter programming using JET APIs
Version: 2.0
IDL ver: 21.4R1

Filter -> Term (1-n) -> Match(1 && 2 && 3 && n) -> Action
Input parameters file is passed as an argument and is a yaml file.

Sample yaml file
---
firewall: 
  - name: TEST-JET-1 #Filtername
    family: inet #family
    delete: leave black if not deleting. add "true" if deleting
    bind: ge-0/0/8.0 #bindinterface
    direction: output #direction of filter applied to intf
    term: # list of terms
    - name: TERM-10  
      adjacency: # can be before <termname> or after <termname>. Firstname should be after/before NULLor null
      match: # 5 tuple match conditions
        sourceip: [192.168.1.1/32,192.168.1.2/32,192.168.2.0/24] # single prefix or list of prefixses including subnet
        destinationip: [192.169.1.1/32,192.169.1.2/32,192.169.2.0/24] # single prefix or list of prefixes inclduing subnet
        sourceport: [80,443,445-446] # single port of list of ports including ranges
        destinationport: [90, 91,100-101] # single port or list of ports inclduing ranges
        protocol: #single int value or list of values including ranges
      action: accept # terminating action
      countername: JET-COUNTER-1 # non terminating action countername

V2
- bind to multiple interfaces
"""

import time, sys, os
import argparse
import grpc
import yaml

from authentication_service_pb2 import *
from authentication_service_pb2_grpc import *
from jnx_firewall_service_pb2 import *
from jnx_firewall_service_pb2_grpc import *
from jnx_common_base_types_pb2 import *
from jnx_common_base_types_pb2_grpc import *
from jnx_common_addr_types_pb2 import *
from jnx_common_addr_types_pb2_grpc import *

import authentication_service_pb2
import authentication_service_pb2_grpc
import jnx_firewall_service_pb2
import jnx_firewall_service_pb2_grpc
import jnx_common_addr_types_pb2
import jnx_common_addr_types_pb2_grpc
import jnx_common_base_types_pb2
import jnx_common_base_types_pb2_grpc

parser = argparse.ArgumentParser()
parser.add_argument("-f", action="store", dest="FILE", help="input yaml file with params")
parser.add_argument("-u", action="store", dest="USER", help="username to connect to the device")
parser.add_argument("-p", action="store", dest="PASSWORD", help="password to connect to device ")
args = parser.parse_args()

DEFAULT_JSD_HOST = '10.85.46.102'
DEFAULT_JSD_PORT = 50051
DEFAULT_CLIENT_ID = '1000'
JET_TIMEOUT = 100

# Match conditions used for firewall filters 
def matchConditions(dstip, srcip, dport, sport, protocol):
    """
    MatchOperation: 1 (Equal), 2 (Not Equal), 0 (Invalid)
    default chosen is 1
    """
    # destination IP addresses match
    if isinstance(dstip, list) and len(dstip) > 1:
        dest_addresses = []
        for i in dstip:
            if "/" in i:
                dstsplit = i.split("/")
                dIP = MatchIpAddress(addr=IpAddress(addr_string=dstsplit[0]), prefix_length=int(dstsplit[1]), operation=1)
                dest_addresses.append(dIP)
            else:
                # /32 subnet 
                dIP = MatchIpAddress(addr=IpAddress(addr_string=i), prefix_length=32, operation=1)
                dest_addresses.append(dIP)
    else:
        # not a list 
        dest_addresses = []
        if "/" in dstip:
            dstsplit = dstip.split("/")
            dIP = MatchIpAddress(addr=IpAddress(addr_string=dstsplit[0]), prefix_length=int(dstsplit[1]), operation=1)
            dest_addresses.append(dIP)
        else:
            dIP = MatchIpAddress(addr=IpAddress(addr_string=dstip), prefix_length=32, operation=1)
            dest_addresses.append(dIP)

    # source IP addresses matches
    if isinstance(srcip, list) and len(srcip) > 1:
        source_addresses = []
        for j in srcip:
            if "/" in j:
                srcsplit = j.split("/")
                sIP = MatchIpAddress(addr=IpAddress(addr_string=srcsplit[0]), prefix_length=int(srcsplit[1]), operation=1)
                source_addresses.append(sIP)
            else:
                #/32 subnet
                sIP = MatchIpAddress(addr=IpAddress(addr_string=j), prefix_length=32, operation=1)
                source_addresses.append(sIP)
    else:
        source_addresses = []
        if "/" in srcip:
            srcsplit = srcip.split("/")
            sIP = MatchIpAddress(addr=IpAddress(addr_string=srcsplit[0]), prefix_length=int(srcsplit[1]), operation=1)
            source_addresses.append(sIP)
        else:
            sIP = MatchIpAddress(addr = IpAddress(addr_string=srcip), prefix_length=32, operation=1)
            source_addresses.append(sIP)

    # destination Port matches
    if isinstance(dport, list) and len(dport) > 1:
        dports = []
        for k in dport:
            if "-" in str(k):
                ksplit = str(k).split("-")
                if int(ksplit[1]) > int(ksplit[0]):
                    DP = MatchPort(min=int(ksplit[0]), max=int(ksplit[1]), operation=2)
                    dports.append(DP)
                elif int(ksplit[1]) == int(ksplit[0]):
                    DP = MatchPort(min=int(ksplit[0]), max=int(ksplit[1]), operation=1)
                    dports.append(DP)
                else:
                    print("Destination ports min port cannot be greater than max port\n")
                    os.exit(1)
            else:
                # exact match on port keeping min and max equal
                DP = MatchPort(min=k, max=k, operation=1)
                dports.append(DP)
    else:
        dports = []
        if "-" in str(dport):
            ksplit = str(dport).split("-")
            if int(ksplit[1]) > int(ksplit[0]):
                DP = MatchPort(min=int(ksplit[0]), max=int(ksplit[1]), operation=2)
                dports.append(DP)
            elif int(ksplit[1]) == int(ksplit[0]):
                DP = MatchPort(min=int(ksplit[0]), max=int(ksplit[1]), operation=1)
                dports.append(DP)
            else:
                print("Destination ports min port cannot be greater than max port\n")
                os.exit(1)
        else:
            # exact match on port keeping min and max equal
            DP = MatchPort(min=dport, max=dport, operation=1)
            dports.append(DP)
            
    # source Port matches 
    if isinstance(sport, list) and len(sport) > 1:
        sports = []
        for l in sport:
            if "-" in str(l):
                lsplit = str(l).split("-")
                if int(lsplit[1]) > int(lsplit[0]):
                    SP = MatchPort(min=int(lsplit[0]), max=int(lsplit[1]), operation=2)
                    sports.append(SP)
                elif int(lsplit[1]) == int(lsplit[0]):
                    SP = MatchPort(min=int(lsplit[0]), max=int(lsplit[1]), operation=1)
                    sports.append(SP)
                else:
                    print("Source ports min port cannot be greater than max port\n")
                    os.exit(1)
            else:
                # exact match on port keeping min and max equal
                SP = MatchPort(min=l, max=l, operation=1)
                sports.append(SP)
    else:
        sports = []
        if "-" in str(sport):
            lsplit = str(sport).split("-")
            if int(lsplit[1]) > int(lsplit[0]):
                SP = MatchPort(min=int(lsplit[0]), max=int(lsplit[1]), operation=2)
                sports.append(SP)
            elif int(lsplit[1]) == int(lsplit[0]):
                SP = MatchPort(min=int(lsplit[0]), max=int(lsplit[1]), operation=1)
                sports.append(SP)
            else:
                print("Source ports min port cannot be greater than max port\n")
                os.exit(1)
        else:
            # exact match on port keeping min and max equal
            SP = MatchPort(min=sport, max=sport, operation=1)
            sports.append(SP)

    # protocols matches
    if protocol != None:
        if isinstance(protocol, list) and len(protocol) > 1:
            protocols = []
            for m in protocol:
                if "-" in str(m):
                    msplit = str(m).split("-")
                    if int(msplit[1]) > int(msplit[0]):
                        P = MatchPort(min=int(msplit[0]), max=int(msplit[1]), operation=2)
                        protocols.append(P)
                    elif int(msplit[1]) == int(msplit[0]):
                        P = MatchPort(min=int(msplit[0]), max=int(msplit[1]), operation=1)
                        protocols.append(P)
                    else:
                        print("min protocol value cannot be greater than max protocol value. value is between 0:255\n")
                        os.exit(1)
                else:
                    # exact match on port keeping min and max equal
                    P = MatchProtocol(min=m, max=m, operation=1)
                    protocols.append(P)
        else:
            protocols = []
            if "-" in str(protocol):
                msplit = str(protocol).split("-")
                if int(msplit[1]) > int(msplit[0]):
                    P = MatchProtocol(min=int(msplit[0]), max=int(msplit[1]), operation=2)
                    protocols.append(P)
                elif int(msplit[1]) == int(msplit[0]):
                    P = MatchProtocol(min=int(msplit[0]), max=int(msplit[1]), operation=1)
                    protocols.append(P)
                else:
                    print("min protocol value cannot be greater than max protocol value. value is between 0:255\n")
                    os.exit(1)
            else:
                # exact match on port keeping min and max equal
                P = MatchProtocol(min=protocol, max=protocol, operation=1)
                protocols.append(P)

        # compile match condition
        match = FilterTermMatchInet(
            ipv4_dst_addrs = dest_addresses,
            ipv4_src_addrs = source_addresses,
            dst_ports = dports,
            src_ports = sports,
            protocols = protocols,
            )
    else:
        match = FilterTermMatchInet(
            ipv4_dst_addrs = dest_addresses,
            ipv4_src_addrs = source_addresses,
            dst_ports = dports,
            src_ports = sports
            )
    return match

def actionConditions(TerminatingAction, NonterminatingAction, countername):
    """
    Non Termination action: ActionCounter count, bool log, bool syslog, bool next_term, bool sample
    termination action: one of (accept, discard, reject, routing_instance_name) 

    Reject would be an ICMP reject: By default 5(ICMP_HOST_UNKNOWN)
    """
    if NonterminatingAction == "count":
        counter = ActionCounter(counter_name = countername)
        actions_nt = FilterTermInetNonTerminatingAction(count = counter)

    if TerminatingAction == "accept":
        actions_t = FilterTermInetTerminatingAction(accept = 1)
    elif TerminatingAction == "discard":
        actions_t = FilterTermInetTerminatingAction(discard = 1)
    elif TerminatingAction == "reject":
        actions_t = FilterTermInetTerminatingAction(reject = 5)
    elif TerminatingAction == "routing-instance":
        # to add routing instance name. Default JET-TEST 
        actions_t = FilterTermInetTerminatingAction(routing_instance_name = "JET-TEST")

    action = FilterTermInetAction(
                    actions_nt = actions_nt,
                    action_t = actions_t
                )
    return action


# Form the list of terms with all match and action conditions
def termAdd(termname, match, action, adjacency):
    #print("adding term {}".format(termname))
    """
    FilterTermOperation: 1(add)
    filterAdjacencyType: 0 (after), 1(before)
    """
    if adjacency != None :
        ad = adjacency.split(" ")
        if ad[0] == "before":
            adjtype = 1
        elif adjacency[0]== "after":
            adjtype = 0
        else:
            adjtype =0

        # before / after term name
        if ad[1] == "NULL" or ad[1] == "null" :
            adj = FilterAdjacency (
                        type = adjtype,
                        term_name = "(null)"
                       )
        else:
            adj = FilterAdjacency (
                        type = adjtype,
                        term_name = ad[1]
                        )

        inetterm = FilterInetTerm(
                term_name = termname,
                term_op = 1,
                adjacency = adj,
                matches = match,
                actions = action
                )

        filterterms = FilterTerm(inet_term = inetterm)
        return filterterms


# Add the firewall filter based on match and action conditions along with multiple terms
def addFirewall(channel, firewallname, filterterms):
    #print("adding firewall {}".format(firewallname))
    """
    Filter families: 
        inet: 1
        inet6: 2
        For more check enum FilterFamilies under jnx_firewall_service.proto

    FilterType:
        classic = 1 ; invalid = 0
    """
    addrequest = FilterAddRequest(
                                name=firewallname,
                                type=1,
                                family=1,
                                terms_list=filterterms 
                                )
    adreq = channel.FilterAdd(addrequest)
    #print(addrequest)
    #print(50*"-")
    #print(adreq)

# Delete firewall filter. 
def filterDelete(channel, fwname):
    #print("Delete filter call\n")
    """
    FilterTermOperation: 2 (delete)
    """
    delrequest = FilterDeleteRequest(name=fwname,
                                 family=1
                                 )
    delreq = channel.FilterDelete(delrequest)
    #print(delreq)


def bindFirewall(channel, firewallfiltername, bindintf, direction):
    """
    filterobjtype: interface(1), fwdtable(2), vlan(3), brg_domain(4)
    Bind Direction: input(1), output(2)
    Filterfamily: inet(1), inet6(2)
    """
    if direction == "input":
        direc = 1
    elif direction == "output":
        direc = 2
    filterobj = FilterObjBindAddRequest(
                                    filter=Filter(name=firewallfiltername, family=1),
                                    obj_type=1,
                                    bind_object=FilterBindObjPoint(interface_name=bindintf),
                                    bind_direction=direc,
                                    bind_family=1
                                )
    breq = channel.FilterBindAdd(filterobj)
    #print(breq)

# Unbind firewall from interface 
def delBindFirewall(channel, firewallfiltername, bindintf, direction):
    if direction == "input":
        direc = 1
    elif direction == "output":
        direc = 2
    objbinddel = FilterObjBindDeleteRequest(
            filter=Filter(name=firewallfiltername, family=1),
            obj_type=1,
            bind_object=FilterBindObjPoint(interface_name=bindintf),
            bind_direction=direc,
            bind_family=1
            )
    channel.FilterBindDelete(objbinddel)

def filterGetStats(channel,fwname,countername):
    print("Get filter {} stats\n".format(fwname))
    getcount = FilterCounterGetRequest(filter_name=fwname, counter_name=countername)
    value = channel.FilterCounterGet(getcount)
    print(value.packets)

#Parse the input parameter file and 
# provision the firewall filter
def handleFilter(channel, mapp):
    for firewall in mapp["firewall"]:
        if firewall["delete"] != None:
            if firewall["bind"] != None:
                if isinstance(firewall["bind"], list) and len(firewall["bind"]) > 1:
                    for intf in firewall["bind"]:
                        delBindFirewall(channel, firewall["name"], intf, firewall["direction"])
                else:
                    delBindFirewall(channel, firewall["name"],firewall["bind"], firewall["direction"])
                filterDelete(channel, firewall["name"])
            else:
                filterDelete(channel, firewall["name"])
        else:
            family = firewall["family"]
            bindintf = firewall["bind"]
            direction = firewall["direction"]
            fwname = firewall["name"]
            fterms = []
            for terms in firewall["term"]:
                if 'adjacency' in terms.keys():
                    adjacency = terms["adjacency"]
                else:
                    adjacency = None
                termname = terms["name"]
                match = matchConditions(terms["match"]["destinationip"],
                                        terms["match"]["sourceip"],
                                        terms["match"]["destinationport"],
                                        terms["match"]["sourceport"],
                                        terms["match"]["protocol"])
                # Non terminating action count used by default
                action = actionConditions(terms["action"], "count", terms["countername"])
                term = termAdd(termname, match, action, adjacency)
                fterms.append(term)
            start = time.time()
            addFirewall(channel, fwname, fterms)
            end = time.time()
            if bindintf:
                # multiple binding interfaces with same direction
                if isinstance(bindintf, list) and len(bindintf) > 1:
                    for intf in bindintf: 
                        bindFirewall(channel, fwname, intf, direction)
                else:
                    # single bind interface
                    bindFirewall(channel, fwname, bindintf, direction)
            print("TOOK {} to program the filter".format(end-start))


# Main definition
def main():
    #channel = grpc.secure_channel(grpc_url, combined_creds, options=[
    #    ('grpc.max_send_message_length', 50 * 1024 * 1024),
    #    ('grpc.max_receive_message_length', 50 * 1024 * 1024)
    #    ])
    channel = grpc.insecure_channel('%s:%d' %(DEFAULT_JSD_HOST, DEFAULT_JSD_PORT))
    stub = authentication_service_pb2_grpc.LoginStub(channel)
    login_response = stub.LoginCheck(authentication_service_pb2.LoginRequest(user_name=args.USER,
                                                                            password=args.PASSWORD,
                                                                            client_id=DEFAULT_CLIENT_ID),JET_TIMEOUT)
    print(login_response)
    firewallchannel = jnx_firewall_service_pb2_grpc.FirewallStub(channel)
    # load input param yaml file
    with open(args.FILE, "r") as f:
        mapp = yaml.safe_load(f)
    handleFilter(firewallchannel, mapp)
    while True:
        e = input("========================\nType quit to Exit\n type getstats <fwname> <countername> to get counter stats\n===================\n")
        if e == "quit" or e == "q":
            break
        if "getstats" in e:
            try:
                split = e.split(" ")
                filterGetStats(firewallchannel, split[1], split[2])
            except:
                print("either filtername or counter name not provided. Please ensure the correct names are provided since they need to be resolved completely\n")
if __name__ == '__main__':
    main()
