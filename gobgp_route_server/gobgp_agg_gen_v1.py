#!/usr/bin/python3.8
# gobgp_agg_gen

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import yaml
import re
import sh
from multiprocessing import Process
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from logging import Formatter
from slacker_log_handler import SlackerLogHandler, NoStacktraceFormatter
import socket
import traceback
import datetime
import json
from pprint import pprint

site = yaml.safe_load(open('agg_gen.yml','r')) # settings
slack_token = site['slack_token'] # slack channel token
agcom = site['agcom'] # conditional static aggregate community tag
rscom = site['rscom'] # route server aggregate community tag
dcscm = site['dcscm'] # plain/decimal conditional static community tag for json
dmtcm = site['dmtcm'] # plain/decimal mitigation community tag for json
dagcm = site['dagcm'] # plain/decimal customer aggregate community tag for json
drscm = site['drscm'] # plain/decimal route server aggregate community tag for json
lp = site['lp'] # set higher local-pref value than customer routes
jcoms = json.dumps([agcom,rscom]) # community list to json array for gobgp 

host = ".".join(socket.gethostname().split(".")[:2])
loc_handler = RotatingFileHandler(filename='gobgp_agg_gen.log', backupCount=7, maxBytes=100 * 1024 ** 2)
logging.getLogger("sh").setLevel(logging.WARNING)
logging.getLogger('').addHandler(loc_handler)
ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
formatter = logging.Formatter('{} - %(name)s - %(levelname)s - %(message)s'.format(ts))
loc_handler.setFormatter(formatter)
loc_handler.setLevel(logging.INFO)
slack_handler = SlackerLogHandler(slack_token,'gobgp_agg_gen_alerts',stack_trace=True)
slacklog = logging.getLogger('gobgp_agg_gen.py python3.8')
slacklog.addHandler(slack_handler)
slack_frmtr = NoStacktraceFormatter('{} - %(name)s - %(levelname)s - %(message)s'.format(ts))
slack_handler.setFormatter(slack_frmtr)
slacklog.setLevel(logging.INFO)
syslog = logging.getLogger('gobgp_agg_gen.py python3.8')
syslog.setLevel(logging.INFO)
syslog_handler = SysLogHandler(address='/dev/log')
syslog_frmtr = NoStacktraceFormatter(' %(name)s - %(levelname)s - %(message)s')
syslog_handler.setFormatter(syslog_frmtr)
syslog.addHandler(syslog_handler)

# For each gre advertised customer route:
# Generate lists of ipv4 /24 prefixes & prefix/next-hop k/v dictionaries
# Return errors for invalid customer routes and continue
def gen_custv4rts():
    jrts = list(filter(None, ((str(sh.jq(sh.gobgp(\
           "global","rib","-a","ipv4","-j"),"-M","-c",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}}))"\
           .format(dcscm)))).split('\n'))))
    custv4rts = []
    custv4rtnhds = []
    for js in jrts:
        try:
            pfx = (json.loads(js))['nlri']['prefix']
            try:
                pnh = IPv4Address((json.loads(js))['attrs'][5]['value']) -1
            except:
                pnh = (json.loads(js))['attrs'][2]['nexthop']
            arsos = list(IPv4Network(pfx).subnets(new_prefix=24))
            ars = []
            ards = []
            for ar in arsos:
                ars.append(str(ar))
                ard = dict([(str(ar),str(pnh))])
                ards.append(ard)
            custv4rts.extend(ars)
            custv4rtnhds.extend(ards)
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_custv4rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    return custv4rts, custv4rtnhds

# For each gre advertised customer route:
# Generate lists of ipv6 /48 prefixes & prefix/next-hop k/v dictionaries
# Return errors for invalid customer routes and continue
def gen_custv6rts():
    jrts = list(filter(None, ((str(sh.jq(sh.gobgp(\
           "global","rib","-a","ipv6","-j"),"-M","-c",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}}))"\
           .format(dcscm)))).split('\n'))))
    custv6rts = []
    custv6rtnhds = []
    for js in jrts:
        try:
            pfx = (json.loads(js))['nlri']['prefix']
            try:
                pnh = IPv6Address((json.loads(js))['attrs'][4]['value']) -1
            except:
                pnh = (json.loads(js))['attrs'][4]['nexthop']
            arsos = list(IPv6Network(pfx).subnets(new_prefix=48))
            ars = []
            ards = []
            for ar in arsos:
                ars.append(str(ar))
                ard = dict([(str(x),str(pnh))])
                ards.append(ard)
            custv6rts.extend(ars)
            custv6rtnhds.extend(ards)
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_custv6rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    return custv6rts, custv6rtnhds

# Generate list of ipv4 /24 prefixes for each mitigation route from mitigation peer, remove duplicates
def gen_mitv4rts():
    mrts = list(filter(None,((sh.jq(sh.gobgp(\
           "global","rib","-a","ipv4","-j"),"-M","-r",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}})) | .nlri.prefix"\
           .format(dmtcm)))).split("\n")))
    mitrts = []
    for mrt in mrts:
        try:
            mrtsnt = IPv4Network(mrt).supernet(new_prefix=24)
            mitrts.append(str(mrtsnt))
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_mitv4rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    mitv4rts = list(dict.fromkeys(mitrts))
    return mitv4rts

# Generate list of ipv6 /48 prefixes for each mitigation route from mitigation peer, remove duplicates
def gen_mitv6rts():
    mrts = list(filter(None,((sh.jq(sh.gobgp(\
           "global","rib","-a","ipv6","-j"),"-M","-r",".[][] | select(contains({{attrs: [{{communities: [{0}]}}]}})) | .nlri.prefix"\
           .format(dmtcm)))).split("\n")))
    mitrts = []
    for mrt in mrts:
        try:
            mrtsnt = IPv6Network(mrt).supernet(new_prefix=48)
            mitrts.append(str(mrtsnt))
        except Exception as e:
            logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' gen_mitv6rts loop error:\n' +\
            str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])
            continue
    mitv6rts = list(dict.fromkeys(mitrts))
    return mitv6rts

# match ipv4 /24 mit routes to /24 cust routes
# inject matching /24 agg routes w/ NH & agg/rs comm's if not already in RIB
# remove old routes if not in addrts
def update_v4rib(custv4rts, custv4rtnhds, mitv4rts):
    addrts = sorted((list(set(mitv4rts).intersection(set(custv4rts)))), key = IPv4Network)
    oldrts = list(filter(None,((sh.jq(sh.gobgp(\
             "global","rib","-a","ipv4","-j"),"-M","-r",".[][] | select\
             (contains({{attrs: [{{communities: [{0}]}}]}}) and contains({{attrs: [{{communities: [{1}]}}]}})) | .nlri.prefix"\
             .format(dagcm,drscm)))).split("\n")))
    delrts = list(set(oldrts).difference(addrts))
    injrts = list(set(addrts).difference(sorted((list(set(oldrts).intersection(set(addrts)))), key = IPv4Network)))
    for injrt in injrts:
        nhi = list(dict.fromkeys([d[str(injrt)] for d in custv4rtnhds if str(injrt) in d]))[0]
        sh.gobgp("global","rib","add",str(injrt),"-a","ipv4","community",jcoms,"local-pref",lp,"origin","igp","nexthop",nhi)
    for delrt in delrts:
        nhd = list(dict.fromkeys([d[str(delrt)] for d in custv4rtnhds if str(delrt) in d]))[0]
        sh.gobgp("global","rib","del",str(delrt),"-a","ipv4","community",jcoms,"local-pref",lp,"origin","igp","nexthop",nhd)

# match ipv6 /48 mit routes to /48 cust routes
# inject matching /48 agg routes w/ NH & agg/rs comm's if not already in RIB
# remove old routes if not in addrts
def update_v6rib(custv6rts, custv6rtnhds, mitv6rts):
    addrts = sorted((list(set(mitv6rts).intersection(set(custv6rts)))), key = IPv6Network)
    oldrts = list(filter(None,((sh.jq(sh.gobgp(\
             "global","rib","-a","ipv6","-j"),"-M","-r",".[][] | select\
             (contains({{attrs: [{{communities: [{0}]}}]}}) and contains({{attrs: [{{communities: [{1}]}}]}})) | .nlri.prefix"\
             .format(dagcm,drscm)))).split("\n")))
    delrts = list(set(oldrts).difference(addrts))
    injrts = list(set(addrts).difference(sorted((list(set(oldrts).intersection(set(addrts)))), key = IPv6Network)))
    for injrt in injrts:
        nhi = list(dict.fromkeys([d[str(injrt)] for d in custv4rtnhds if str(injrt) in d]))[0]
        sh.gobgp("global","rib","add",str(injrt),"-a","ipv6","community",jcoms,"local-pref",lp,"origin","igp","nexthop",nhi)
    for delrt in delrts:
        nhd = list(dict.fromkeys([d[str(delrt)] for d in custv4rtnhds if str(delrt) in d]))[0]
        sh.gobgp("global","rib","del",str(delrt),"-a","ipv6","community",jcoms,"local-pref",lp,"origin","igp","nexthop",nhd)

# functions to update active agg routes on route server ipv4 RIB
def ipv4_fs():
    try:
        custv4rts, custv4rtnhds = gen_custv4rts()
        mitv4rts = gen_mitv4rts()
        update_v4rib(custv4rts, custv4rtnhds, mitv4rts)
        logging.getLogger('gobgp_agg_gen.py python3.8').info('{} ipv4 agg routes updated'.format(host))
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' ipv4 function set error:\n' + 
                           str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

# functions to update active agg routes on route server ipv6 RIB
def ipv6_fs():
    try:
        custv6rts, custv6rtnhds = gen_custv6rts()
        mitv6rts = gen_mitv6rts()
        update_v6rib(custv6rts, custv6rtnhds, mitv6rts)
        logging.getLogger('gobgp_agg_gen.py python3.8').info('{} ipv6 agg routes updated'.format(host))
    except Exception as e:
        logging.getLogger('gobgp_agg_gen.py python3.8').error(host + ' ipv6 function set error:\n' + 
                           str(traceback.format_exc()).split('\n')[2] + '\n' + str(traceback.format_exc()).split('\n')[-2])

# execute ipv4/ipv6 function sets with multiprocessing
if __name__ == '__main__':
  p1 = Process(target=ipv4_fs)
  p1.start()
  p2 = Process(target=ipv6_fs)
  p2.start()
  p1.join()
  p2.join()

