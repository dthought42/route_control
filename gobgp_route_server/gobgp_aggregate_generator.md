# gobgp_agg_gen.py
GoBGP Virtual Route Server Aggregate Internet Route Generator - Python3.8 - IPv4 and IPv6 unicast families.

The script acts entirely on the route table of the GoBGP virtual router daemon running on a Linux instance. It uses multiprocessing and completes all functions in less than a minute, so it works well as a 1 minute cron job and consumes minimal resources. Whatever scale is needed on the instance to support the size of the GoBGP route-server route table is fine with this script. 

Both IPv4 and IPv6 task sets run in parallel. Core functions of the script rely on the Python ipaddress library.
For both ipv4/ipv6 tables:

    1. Customer routes with Originator attribute(if found) or next-hop attribute and tagged with a "customer" community, 
       learned by the GoBGP route server from the customer router and present in the route table are collected as json
       via sh. 
    2. Arbor TMS/other DDOS appliance mitigation routes/or just route redirect - tagged with a "mitigation"
       community, learned by the GoBGP route server and present in the route table are collected as json via sh.
    3. Respective ipv4/ipv6 route sets are parsed into /24 (/48 ipv6) inclusive equivalents:
       -The larger customer prefixes/supernets are converted to /24 (/48 ipv6) sets.
       -The smaller mitigation/redirect subnets are converted to the single larger /24 (/48 ipv6) subnet.
    4. The sets are matched, and new /24 (/48 ipv6) aggregate routes are generated.
       The script then injects these new tagged routes with new community, local-pref, and next-hop attributes, 
       into the GoBGP route server v4/v6 route tables.  
    5. On each run the script also actively removes previously injected aggregate routes if the customer/mitigation
       match list element is no longer present. 
    6. Designed to work well with a single IPv4 or IPv6 route table for all peers involved. 
    7. An edge router peer can then learn the local-pref preferred tagged agg routes from the GoBGP route server 
       and act on them with outbound provider peer route policies to be advertised to upstream providers for
       scrubbing, blackholing, route redirect.

