"""
Version: 2.0
Author: aprabh@juniper.net
Description: Generate scaled config input file to program 5 tuple filter using JET APIs
This will be generate a yaml file with all the filter params and would be used as input
to the collector_v2.py file.
"""
import yaml
import random
from netaddr import *
from pprint import pprint
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-term', action='store', dest='TERM', type=str, default=None)
args=parser.parse_args()

"""
Inputs
"""
# Source IP network. Source address will be a /32 and will be incremented by 1
SRC_IP = '100.1.0.0/24'
# Dest IP network. DEst address will be a /32 and will be incremented by 1
DST_IP = '200.1.0.0/24'
# a random port between 1 and MAX_SOURCE_PORT would be generated and used 
MAX_SOURCE_PORT = 1000
# a random port between 1 and MAX_DEST_PORT would be generated and used 
MAX_DST_PORT = 1000
# a random choice between the list of protocol numbers mentioned. This will be an IANA allocated protocol val.
PROTOCOL = [6, 17]
# single or list ["intf1, intf2..]. The firewall will be bound to the mentioned interfaces 
#BIND_INTF = ["ge-0/0/2.0", "ge-0/0/3.0"]
BIND_INTF = "et-4/1/2.0"
# Total number of firewalls created
NUM_FIREWALL = 1
# Number of terms for the firewall.
NUM_TERMS = int(args.TERM)
# Direction of the filter applied on the interface. input/output
DIRECTION = "input"
# Default action on the filter. accept/discard
DEFAULT_ACTION = "accept"

"""
Main function call
"""
def main():
    NET_SRC_IP = IPNetwork(SRC_IP)
    NET_DST_IP = IPNetwork(DST_IP)
    FINAL = {}
    FIREWALL = {}
    FIREWALL_LIST = []
    TERM = {}
    LIST_TERM = []
    MATCH = {}
    
    for firewall in range(0, NUM_FIREWALL):
        FIREWALL["name"] = "FIREWALL-"+str(firewall)
        FIREWALL["family"] = "inet"
        FIREWALL["bind"] = BIND_INTF
        FIREWALL["direction"] = DIRECTION
        FIREWALL["delete"] = None
        for terms in range(0, NUM_TERMS):
            TERM["name"] = "TERM-"+str(terms)
            if terms == 0:
                TERM["adjacency"] = "after NULL"
            else:
                TERM["adjacency"] = "after TERM-"+str(terms-1)
            MATCH["sourceip"] = str(NET_SRC_IP.ip+terms+1)
            MATCH["destinationip"] = str(NET_DST_IP.ip+terms+1)
            MATCH["sourceport"] = random.randint(1, MAX_SOURCE_PORT)
            MATCH["destinationport"] = random.randint(1, MAX_DST_PORT)
            MATCH["protocol"] = random.choice(PROTOCOL)
            TERM["match"] = MATCH
            TERM["action"] = DEFAULT_ACTION
            TERM["countername"] = "JET-COUNTER-"+str(terms)
            LIST_TERM.append(TERM)
            MATCH = {}
            TERM = {}
        FIREWALL["term"] = LIST_TERM
        FIREWALL_LIST.append(FIREWALL)
        FIREWALL = {}
    FINAL["firewall"]=FIREWALL_LIST
    
    with open('scale_test_'+str(NUM_TERMS)+'_terms.yaml', 'w') as f:
        f.write(yaml.safe_dump(FINAL, default_flow_style=False))
    
    print("generated yaml file: scale_test_{}_terms.yaml".format(str(NUM_TERMS)))

if __name__ == "__main__":
    main()
