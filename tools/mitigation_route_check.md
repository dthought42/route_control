# mitcheck.py
Command line tool to check an aggregate mitigation or route-control redirect route. 

The script uses threading to check all sites at once for a given /24 route:

    1. Check the site GoBGP route-server to determine if the route is locally injected and get the Arbor TMS source.
    2. Check the site Juniper edge router to determine the route source, type of route, and as-path/prepends if present.
    3. get advertised transit neighbors for upstream mitigation/re-direct route from the site Juniper edge router.  
    4. Combine/format all route data and print.

