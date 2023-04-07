This is a jet app for Route Leaking from foo.inet.0 -> inet.0 to attract traffic from inet.0 -> foo.inet.0
currently Junos rib groups cannot leak L3vpn routes learnt from bgp inet-vpn session to inet.0 table. only routes of same family type can be leaked. This app helps overcome that issue by reading through routes received and adding a static route back on inet.0 table pointing to an indirect next hop resolving from foo.inet.0 table based on a IP and community defined for a particular service. 

## Copy file
Copy the route-leak.py file to /var/db/scripts/jet

## Configuration needed
```
set routing-options programmable-rpd purge-timeout 1000
set policy-options policy-statement ANALYZER term 20 then analyze
set policy-options policy-statement ANALYZER term 20 then accept
set protocols bgp group L3VPN neighbor 10.1.1.1 import ANALYZER
set routing-options resolution rib inet.0 resolution-ribs FOO.inet.0
set routing-options resolution rib inet.0 resolution-ribs inet.3
```

## Configuration for app
```
set system extensions extension-service application file route-leak.py arguments "-nhip 98.98.98.98 -comm 9191:9191"
set system extensions extension-service application file route-leak.py daemonize
set system extensions extension-service application file route-leak.py username root
```

## Verify
```
root@vmx# run show programmable-rpd clients
RPD global purge timeout: 1000
RPD Server connected client details:
ClientIdentifier              PurgeTimer Status  Timeout Protocol         NumRoutes
1000  Up              BGP-Static            4

root@vmx# run show route programmed

inet.0: 32 destinations, 37 routes (32 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

98.0.0.1/32        *[BGP-Static/5/-101] 00:07:06, metric2 0
                    >  to 192.170.1.14 via ae0.2, Push 17, Push 300576(top)
98.0.0.2/32        *[BGP-Static/5/-101] 00:07:06, metric2 0
                    >  to 192.170.1.14 via ae0.2, Push 17, Push 300576(top)
98.0.0.3/32        *[BGP-Static/5/-101] 00:07:06, metric2 0
                    >  to 192.170.1.14 via ae0.2, Push 17, Push 300576(top)
98.0.0.4/32        *[BGP-Static/5/-101] 00:07:06, metric2 0
                    >  to 192.170.1.14 via ae0.2, Push 17, Push 300576(top)

root@dcu# run show system processes | grep route-leak
50149  -  R        1:13.06 /usr/libexec/ui/cscript -mjet -Q3 -j -f route-leak.py -a -nhip 98.98.98.98 -a -comm 9191:9191 -Jroot
```

## Logs
Logs are written to /var/log/route-leak.log

root@dcu# run show log route-leak.log
2023-02-06 03:42:54 root - INFO - True
2023-02-06 03:42:54 root - INFO - Adding route 98.0.0.2
2023-02-06 03:42:54 root - INFO - Adding route 98.0.0.3
2023-02-06 03:42:54 root - INFO - Adding route 98.0.0.1
2023-02-06 03:42:54 root - INFO - Adding route 98.0.0.4
2023-02-06 03:43:18 root - INFO - Deleting route 98.0.0.2
2023-02-06 03:43:18 root - INFO - Deleting route 98.0.0.3
2023-02-06 03:43:18 root - INFO - Deleting route 98.0.0.1
2023-02-06 03:43:18 root - INFO - Deleting route 98.0.0.4
2023-02-06 03:43:20 root - INFO - Adding route 98.0.0.2
2023-02-06 03:43:20 root - INFO - Adding route 98.0.0.3
2023-02-06 03:43:21 root - INFO - Adding route 98.0.0.1
2023-02-06 03:43:21 root - INFO - Adding route 98.0.0.4
