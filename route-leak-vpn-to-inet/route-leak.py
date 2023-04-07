#  Author: Aravind Prabhakar
#  Version: 1.0
#  Date: 02-03-2023
#  Description: pRPD app to perform route leaking from foo.inet.0 -> inet.0
#  File should be placed under /var/db/scripts/jet 
#  The below should be added on the router where route needs to be 
#  leaked on the BGP L3VPN session towards the VPN RR
#
#  set routing-options programmable-rpd purge-timeout 1000 
#  set policy-options policy-statement ANALYZER term 20 then analyze
#  set policy-options policy-statement ANALYZER term 20 then accept
#  set protocols bgp group L3VPN neighbor 10.1.1.1 import ANALYZER
#  set routing-options resolution rib inet.0 resolution-ribs FOO.inet.0
#  set routing-options resolution rib inet.0 resolution-ribs inet.3

#!/usr/bin/python3
import sys, os
sys.path.append("/opt/lib/python3.7/site-packages/jnpr/jet/grpc_services/")

import argparse 
import grpc
import logging
from logging import handlers

import authentication_service_pb2
import prpd_common_pb2
import jnx_addr_pb2
import bgp_route_service_pb2

from bgp_route_service_pb2 import *
from jnx_addr_pb2 import *
from prpd_common_pb2 import *
from authentication_service_pb2 import *

# file logger
logging.basicConfig(filename='/var/log/route-leak.log', filemode='w', format='%(asctime)s %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

parser = argparse.ArgumentParser()
parser.add_argument("-nhip", action="store", dest="NHIP", help="protocol nexthop to be used. This would be the loopback in VRF/pe-ce link IP")
parser.add_argument("-comm", action="store", dest="COMM", help="unique BGP comunity which identifies the customer")
args = parser.parse_args()

DEFAULT_JSD_HOST = '192.167.1.6'
DEFAULT_JSD_PORT = 50051
DEFAULT_CLIENT_ID = '03422'
TIMEOUT = 1000
USER = 'root'
PASSWORD = 'juniper123'
RESOLUTION_NHIP = args.NHIP
CUSTOMER_COMMUNITY = args.COMM


# Return dest table name 
def destTableName(desttable):
    table=RouteTable()
    table.rtt_name.name=desttable
    return table


# Init bgp session
def BgpInit(bgp):
    strBgpReq = BgpRouteInitializeRequest()
    result = bgp.BgpRouteInitialize(strBgpReq)
    if ((result.status != BgpRouteInitializeReply.SUCCESS) and
        (result.status != BgpRouteInitializeReply.SUCCESS_STATE_REBOUND)):
        logging.info ('Error on Initialize')


# Add route 
def RouteAdd(bgp, dest_prefix, pfxlen, nhip):
    logging.info("Adding route {} ".format(dest_prefix))
    nhip = IpAddress(addr_string=nhip)
    bgpTable = destTableName("inet.0")
    dstpfx =  RoutePrefix(inet = IpAddress(addr_string=dest_prefix)) 
    routeparams = BgpRouteEntry(dest_prefix=dstpfx, dest_prefix_len=pfxlen, table=bgpTable, protocol_nexthops=[nhip], protocol=PROTO_BGP_STATIC)
    upd = BgpRouteUpdateRequest(bgp_routes = [routeparams])
    bgp.BgpRouteAdd(upd)


# Route delete
def RouteDel(bgp, dest_prefix, pfxlen):
    logging.info("Deleting route {} ".format(dest_prefix))
    bgpTable = destTableName("inet.0")
    dstpfx =  RoutePrefix(inet = IpAddress(addr_string=dest_prefix)) 
    routematch = BgpRouteMatch(dest_prefix=dstpfx, dest_prefix_len=pfxlen, table=bgpTable, protocol=PROTO_BGP_STATIC)
    upd = BgpRouteRemoveRequest(bgp_routes = [routematch])
    bgp.BgpRouteRemove(upd)

def main():
    channel = grpc.insecure_channel('%s:%d' %(DEFAULT_JSD_HOST, DEFAULT_JSD_PORT))
    stub=authentication_service_pb2.LoginStub(channel)
    login_response = stub.LoginCheck(authentication_service_pb2.LoginRequest(user_name=USER, password=PASSWORD, client_id=DEFAULT_CLIENT_ID), TIMEOUT)
    logging.info(login_response.result)
    
    bgp = bgp_route_service_pb2.BgpRouteStub(channel)
    
    #Initialize BGP req
    BgpInit(bgp)
    routeReg = bgp_route_service_pb2.BgpRouteMonitorRegisterRequest(route_count=1000)
    monitor = bgp.BgpRouteMonitorRegister(routeReg)
    
    for entry in monitor:
        for i in entry.monitor_entries:
            if i.operation == 1:
                # Del route
                prefix = i.bgp_route.dest_prefix.inetvpn.vpn_addr.addr_string
                pfxlen = i.bgp_route.dest_prefix_len
                commlist =  i.bgp_route.communities.com_list
                for comm in commlist:
                    if (comm.community_string) == CUSTOMER_COMMUNITY:
                        RouteDel(bgp, prefix, pfxlen)    
            elif i.operation == 0:
                # Add route
                prefix = i.bgp_route.dest_prefix.inetvpn.vpn_addr.addr_string
                pfxlen = i.bgp_route.dest_prefix_len
                commlist =  i.bgp_route.communities.com_list
                for comm in commlist:
                    if (comm.community_string) == CUSTOMER_COMMUNITY:
                        RouteAdd(bgp, prefix, pfxlen, RESOLUTION_NHIP)


if __name__ == "__main__" :
    main()
