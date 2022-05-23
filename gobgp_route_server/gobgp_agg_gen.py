#!/usr/bin/python3.8
# gobgp_agg_gen
# David Weber - Network Automation Engineer

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import yaml
import re
import sh
import multiprocessing as mp
from multiprocessing import Process
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from logging import Formatter
import socket
import traceback
import datetime
import json
from pytricia import PyTricia
import time 
from time import time as dt
from pprint import pprint

host = '.'.join(socket.gethostname().split('.')[:2])
site = yaml.safe_load(open('agg_gen.yml','r')) # settings
slack_token = site['slack_token'] # slack channel token
scoms = site['scoms'][host.split('.')[1]] # site specific aggregate communities
btecm = site['btecm'] # bgp-te type-customer-originated community
agcom = site['agcom'] # conditional static aggregate community
rscom = site['rscom'] # route server aggregate community
dcscm = site['dcscm'] # plain/decimal conditional static community
dmtcm = site['dmtcm'] # plain/decimal mitigation community
dagcm = site['dagcm'] # plain/decimal customer aggregate community
drscm = site['drscm'] # plain/decimal route server aggregate community
btelp = str(site['btelp']) # bgp_te aggregate route local-pref
brdlp = str(site['brdlp']) # bgp_redirect aggregate route local-pref

loc_handler = RotatingFileHandler(filename='gobgp_agg_gen.log', backupCount=7, maxBytes=100 * 1024 ** 2)
logging.getLogger("sh").setLevel(logging.WARNING)
logging.getLogger('').addHandler(loc_handler)
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
formatter = logging.Formatter('{} - %(name)s - %(levelname)s - %(message)s'.format(ts))
loc_handler.setFormatter(formatter)
loc_handler.setLevel(logging.INFO)
syslog = logging.getLogger('gobgp_agg_gen.py python3.8')
syslog.setLevel(logging.INFO)
syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(formatter)
syslog.addHandler(syslog_handler)
pyt6 = PyTricia(128)
pyt4 = PyTricia(32)

### Generate v4/v6 /24/48 prefix for each mitigation route(s) from mitigation peer, remove duplicates ###
def gen_mitv4rts():
    mrts = list(filter(None,((sh.jq(sh.gobgp(\
           "global","rib","-a","ipv4","-j"),"-M","-r",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}})) | .nlri.prefix"\
           .format(dmtcm)))).split("\n")))
    mitrts = []
    for mrt in mrts:
        try:
            mrtsnt = IPv4Network(mrt).supernet(new_prefix=24)
            mitrts.append(mrtsnt)
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_mitv4rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    mitv4rts = list(dict.fromkeys(mitrts))
    return mitv4rts

def gen_mitv6rts():
    mrts = list(filter(None,((sh.jq(sh.gobgp(\
           "global","rib","-a","ipv6","-j"),"-M","-r",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}})) | .nlri.prefix"\
           .format(dmtcm)))).split("\n")))
    mitrts = []
    for mrt in mrts:
        try:
            mrtsnt = IPv6Network(mrt).supernet(new_prefix=48)
            mitrts.append(mrtsnt)
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_mitv6rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    mitv6rts = list(dict.fromkeys(mitrts))
    return mitv6rts

# Generate v4/v6 /24/48 aggregate route prefixes:
# With nested multiprocessing for each gre advertised customer route:
# v4/v6 customer json/mitigation prefix, Patricia trie matching - PyTricia
# - https://github.com/jsommers/pytricia
# - Generate lists of ipv4/v6 /24/48 prefixes & attribute dictionary w/ prefix key
# - Dynamic dictionary values: community set, next-hop, local-pref
# - Log errors for invalid customer routes and continue

def gen_aggv4rts(js,mtrs):
    try:
        try:
            pnh = IPv4Address(list(dict.fromkeys([d['value'] for d in \
                    ((json.loads(js))['attrs']) if d['type']==9]))[0]) -1
            rcoms = [agcom, rscom, btecm]
            rcoms += scoms
            lp = btelp
        except:
            pnh = list(dict.fromkeys([d['nexthop'] for d in ((json.loads(js))['attrs']) if d['type']==3]))[0]
            rcoms = [agcom, rscom]
            rcoms += scoms
            lp = brdlp
        aggv4attrds_w = [{str(ar): [str(pnh), json.dumps(rcoms), lp]} for ar in mtrs]
        return aggv4attrds_w
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_custv4rts loop error:\n' +\
        str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

def gen_aggv4rts_wp(mitv4rts):
    jcrts = list(filter(None, ((str(sh.jq(sh.gobgp(\
           "global","rib","-a","ipv4","-j"),"-M","-c",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}}))"\
           .format(dcscm)))).split('\n'))))
    [pyt4.insert(IPv4Network((json.loads(js))['nlri']['prefix']), js) for js in jcrts]
    jrts, mtrs = map(list, zip(*([(pyt4.get(mitv4rt), mitv4rt) for mitv4rt in mitv4rts if pyt4.get_key(mitv4rt) != None])))
    aggv4attrds = []
    with ProcessPoolExecutor(8) as executor:
        futures = [executor.submit(gen_aggv4rts,js,mtrs) for js in jrts]
        for future in as_completed(futures):
            if future.result() != None:
                aggv4attrds += future.result()
    return aggv4attrds

def gen_aggv6rts(js,mtrs):
    try:
        try:
            pnh = IPv6Address(list(dict.fromkeys([d['value'] for d in \
                    ((json.loads(js))['attrs']) if d['type']==9]))[0]) -1
            rcoms = [agcom, rscom, btecm]
            rcoms += scoms
            lp = btelp
        except:
            pnh = list(dict.fromkeys([d['nexthop'] for d in ((json.loads(js))['attrs']) if d['type']==14]))[0]
            rcoms = [agcom, rscom]
            rcoms += scoms
            lp = brdlp
        aggv6attrds_w = [{str(ar): [str(pnh), json.dumps(rcoms), lp]} for ar in mtrs]
        return aggv6attrds_w
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_custv6rts loop error:\n' +\
        str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

def gen_aggv6rts_wp(mitv6rts, pyt6):
    jcrts = list(filter(None, ((str(sh.jq(sh.gobgp(\
           "global","rib","-a","ipv6","-j"),"-M","-c",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}}))"\
           .format(dcscm)))).split('\n'))))
    [pyt6.insert(IPv6Network((json.loads(js))['nlri']['prefix']), js) for js in jcrts]
    jrts, mtrs = map(list, zip(*([(pyt6.get(mitv6rt), mitv6rt) for mitv6rt in mitv6rts if pyt6.get_key(mitv6rt) != None])))
    aggv6attrds = []
    with ProcessPoolExecutor(8) as executor:
        futures = [executor.submit(gen_aggv6rts,js,mtrs) for js in jrts]
        for future in as_completed(futures):
            if future.result() != None:
                aggv6attrds += future.result()
    return aggv6attrds

# inject /24/48 agg routes w/ attributes if not already in RIB
# remove old routes if not in addrts

def update_v4rib(aggv4attrds):
    try:
        addrts = list(dict.fromkeys([k for d in aggv4attrds for k in d.keys()]))
        oldrts = list(filter(None,((sh.jq(sh.gobgp(\
                 "global","rib","-a","ipv4","-j"),"-M","-r",".[][] | select\
                 (contains({{attrs: [{{communities: [{0}]}}]}}) and contains({{attrs: [{{communities: [{1}]}}]}})) | .nlri.prefix"\
                 .format(dagcm,drscm)))).split("\n")))
        delrts = list(set(oldrts).difference(addrts))
        injrts = list(set(addrts).difference(sorted((list(set(oldrts).intersection(set(addrts)))), key = IPv4Network)))
        for injrt in injrts:
            try:
                nhi = list(dict.fromkeys([d[str(injrt)][0] for d in aggv4attrds if str(injrt) in d]))[0]
                cmi = list(dict.fromkeys([d[str(injrt)][1] for d in aggv4attrds if str(injrt) in d]))[0]
                lpi = list(dict.fromkeys([d[str(injrt)][2] for d in aggv4attrds if str(injrt) in d]))[0]
                sh.gobgp("global","rib","add",str(injrt),"-a","ipv4","community",cmi,"local-pref",lpi,"origin","igp","nexthop",nhi)
            except Exception as e:
                logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v4rib inject route error:\n' +\
                str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
                continue
        for delrt in delrts:
            try:
                sh.gobgp("global","rib","del",delrt,"-a","ipv4","community",rscom)
            except Exception as e:
                logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v4rib delete route error:\n' +\
                str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
                continue
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v4rib function error:\n' +\
        str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

def update_v6rib(aggv6attrds):
    try:
        addrts = list(dict.fromkeys([k for d in aggv6attrds for k in d.keys()]))
        oldrts = list(filter(None,((sh.jq(sh.gobgp(\
                 "global","rib","-a","ipv6","-j"),"-M","-r",".[][] | select\
                 (contains({{attrs: [{{communities: [{0}]}}]}}) and contains({{attrs: [{{communities: [{1}]}}]}})) | .nlri.prefix"\
                 .format(dagcm,drscm)))).split("\n")))
        delrts = list(set(oldrts).difference(addrts))
        injrts = list(set(addrts).difference(sorted((list(set(oldrts).intersection(set(addrts)))), key = IPv6Network)))
        for injrt in injrts:
            try:
                nhi = list(dict.fromkeys([d[str(injrt)][0] for d in aggv6attrds if str(injrt) in d]))[0]
                cmi = list(dict.fromkeys([d[str(injrt)][1] for d in aggv6attrds if str(injrt) in d]))[0]
                lpi = list(dict.fromkeys([d[str(injrt)][2] for d in aggv6attrds if str(injrt) in d]))[0]
                sh.gobgp("global","rib","add",str(injrt),"-a","ipv6","community",cmi,"local-pref",lpi,"origin","igp","nexthop",nhi)
            except Exception as e:
                logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v6rib inject route error:\n' +\
                str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
                continue
        for delrt in delrts:
            try:
                sh.gobgp("global","rib","del",delrt,"-a","ipv6","community",rscom)
            except Exception as e:
                logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v6rib delete route error:\n' +\
                str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
                continue
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' update_v6rib error:\n' +\
        str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

# functions to update active agg routes on route server - ipv4/ipv6 RIBs
def ipv4_fs():
    try:
        mitv4rts = gen_mitv4rts()
        aggv4attrds = gen_aggv4rts_wp(mitv4rts)
        update_v4rib(aggv4attrds)
        logging.getLogger('gobgp_agg_gen.py python3.8').info('{} ipv4 agg routes updated'.format(host))
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' ipv4 function set error:\n' + 
                           str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

def ipv6_fs():
    try:
        mitv6rts = gen_mitv6rts()
        aggv6attrds = gen_aggv6rts_wp(mitv6rts,pyt6)
        update_v6rib(aggv6attrds)
        logging.getLogger('gobgp_agg_gen.py python3.8').info('{} ipv6 agg routes updated'.format(host))
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' ipv6 function set error:\n' + 
                           str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

# execute ipv4/ipv6 function groups with multiprocessing
if __name__ == '__main__':
    mp.set_start_method('fork')
    p1 = mp.Process(target=ipv4_fs)
    p2 = mp.Process(target=ipv6_fs)
    p1.start()
    p2.start()
    p1.join()
    p2.join()

