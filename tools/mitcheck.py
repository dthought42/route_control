#!/usr/bin/python3

from jnpr.junos import Device
from lxml import etree
import jxmlease
import xmltodict
from getpass import getpass,getuser
import dns.resolver,dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import paramiko
from pprint import pprint
import yaml
import re
import json
import time

user = getuser()
pw = getpass("Enter Password for user {0}: ".format(user)) 
settings = yaml.safe_load(open('settings.yml','r'))
totalsites = settings['totalsites'] # total number of sites #
sites = settings['sites'] # site host list #
dmtcm = settings['dmtcm'] # # plain/decimal mitigation community tag for json #
cscom = settings['cscom'] # customer route community tag #
agcom = settings['agcom'] # aggregate route community tag #
transit1 = settings['transit1'] # transit provider #
transit2 = settings['transit2'] # transit provider #
now = datetime.now()
dts = now.strftime("%Y-%d-%m %H:%M:%S")

# get tms mitigation source prefix for upstream mitigation agg route from site GoBGP route-server #
def get_tms_mits(user,pw,mitpfx,site):
    rsh = 'rs01.' + site # site route-server host #
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(rsh, username=user, password=pw)
    mitip = '"' + '.'.join(mitpfx.split('/')[0].split('.')[0:3]) + '.' + '"'
    cmd = "/home/go/gobgp global rib -j | jq '.[] | .[] | select(contains({nlri: {prefix: " + mitip + "}})\
            and contains({attrs: [{communities: [1304503180]}]}))'"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read()
    sder = stderr.read()
    tmsrtl = []
    if out:
        tmsrtsls = re.sub(r'}{','}}{{',(re.sub(r' +','',(re.sub(r'\n','',(out.decode('ascii'))))))).split('}{')
        for js in tmsrtsls:
            tmsrtsdp = (json.loads(js))['nlri']['prefix'] 
            tmsrtsdn = (json.loads(js))['attrs'][2]['nexthop']
            try:
                dnsq = dns.reversename.from_address(tmsrtsdn)
                tmshost = (str(dns.resolver.query(dnsq,"PTR")[0]))[:-21]
            except:
                tmshost = 'dns_not_found'
            tmsrt = 'TMS {0}({1}) advertising mitigation source prefix {2} to {3} for upstream mitigation agg route {4}'\
                    .format(tmshost,tmsrtsdn,tmsrtsdp,rsh,mitpfx) 
            tmsrtl.append(tmsrt)
    ssh.close()
    return tmsrtl

# get upstream aggregate route source, type of route, as-path/prepends if applicable from site Juniper edge router #
def get_sr_mits(user,pw,mitpfx,site,dev,cscom,agcom):
    rpc_rt = dev.rpc.get_route_information({'format':'json'},destination=mitpfx,table='inet.0',community=agcom,best=True,\
            detail=True,active_path=True)
    try:
        rt = rpc_rt['route-information'][0]['route-table'][0]['rt'][0]['rt-entry'][0]['gateway'][0]['data']
        rtdcl = rpc_rt['route-information'][0]['route-table'][0]['rt'][0]['rt-entry'][0]['communities'][0]['community']
        rtcl = [d['data'] for d in rtdcl if d['data'] == cscom]
        try:
            rtap = rpc_rt['route-information'][0]['route-table'][0]['rt'][0]['rt-entry'][0]['as-path'][0]['data']
        except:
            rtap = ''
    except:
        rt = ''
        rtcl = []
    if rt != '' and cscom not in rtcl:
        try:
            rtnq = dns.reversename.from_address(rt)
            rtn = (str(dns.resolver.query(rtnq,"PTR")[0]))[:-21]
        except:
            rtn = 'dns_not_found'
        if rtn.split('.')[1] == site:
            if rt.split('.')[3] == '224':
                if rtap != '':
                    rtno = (\
        '**** Transit facing CUSTOMER ROUTE {0} SOURCED locally from gre01.{1} ****\nLearning cust re-direct route: '\
        .format(mitpfx,site) + mitpfx + ' from ' + rt + ' - ' + rtn + '\n*** ' + rtap + '\n*** communities: ' + \
        (' '.join([d['data'] for d in rtdcl])) + '\n')
                else:
                    rtno = \
        '**** Transit facing CUSTOMER ROUTE {0} SOURCED locally from gre01.{1} ****\nLearning cust re-direct route: '\
        .format(mitpfx,site) + mitpfx + ' from ' + rt + ' - ' + rtn + '\n'
            elif rt.split('.')[3] == '3':
                rtno = \
        '**** Transit facing AGG ROUTE {0} SOURCED locally from rs01.{1} ****\nLearning mitigation agg route: '\
        .format(mitpfx,site) + mitpfx + ' from ' + rt + ' - ' + rtn + '\n'
        else:
            if 'Originator ID: 172.16' in rtap:
                rtno = 'Learning cust re-direct route: ' + mitpfx + ' from ' + rt + ' - ' + rtn + '\n*** ' + rtap\
                        + '\n*** communities: ' + (' '.join([d['data'] for d in rtdcl])) + '\n'   
            else:
                rtno = 'Learning mitigation agg route: ' + mitpfx + ' from ' + rt + ' - ' + rtn + '\n'
    else:
        rtno = ''
    return rtno

# get advertised transit neighbors for upstream mitigation/re-direct route from Juniper edge router #
# - combine and return all route data #
def get_mit_advnei(user,pw,mitpfx,site,tmsrtl,rtno,dev,host):
    rpc_ns = dev.rpc.get_bgp_neighbor_information()
    ns = jxmlease.parse(etree.tostring(rpc_ns, pretty_print=True, encoding='unicode'))\
            ['bgp-information']['bgp-peer']
    neighs = '\n'.join([(str(d['peer-address'])).split('+')[0] for d in ns if d['peer-group'] in \
            {transit1,transit2}]).split('\n')
    rsts = []
    for nei in neighs:
        rpc_ad = dev.rpc.get_route_information(advertising_protocol_name='bgp', neighbor=nei)
        try:
            ad = xmltodict.parse(etree.tostring(rpc_ad, pretty_print=True, encoding='unicode'))\
                    ['route-information']['route-table']
            admits = '\n'.join([str(d['rt-destination']) for d in list(ad['rt'])]).split('\n')
        except:
            admits = []
        if mitpfx in admits:
            advpfx = mitpfx
            try:
                neiq = dns.reversename.from_address(nei)
                nei_dns = str(dns.resolver.query(neiq,"PTR")[0])
            except:
                nei_dns = 'dns_not_found'
            rst = 'Advertising prefix: ' + advpfx + ' to transit peer {0} - {1}'.format(nei,nei_dns)
            rsts.append(rst)
    if rtno:
        if tmsrtl:
            rsts_output = host + ':\n' + rtno + '\n'.join(rsts) + '\n\n' + '\n'.join(tmsrtl) + '\n'
        else:
            rsts_output = host + ':\n' + rtno + '\n'.join(rsts) + '\n'
    else:
        if tmsrtl:
            rsts_output = host + ':\n' + '\n'.join(rsts) + '\n\n' + '\n'.join(tmsrtl) + '\n'
        elif rsts:
            rsts_output = host + ':\n' + '\n'.join(rsts) + '\n'
        else:
            rsts_output = ''
    return rsts_output

# functions to collect routing data for a given upstream agg route #
def get_routing_data(user,pw,mitpfx,site,cscom,agcom):
    tmsrtl = get_tms_mits(user,pw,mitpfx,site)
    host = 'sr01.' + site # site router host #
    dev = Device(host=host, user=user, password=pw, port='22', normalize=True)
    dev.open()
    rtno = get_sr_mits(user,pw,mitpfx,site,dev,cscom,agcom)
    rsts_output = get_mit_advnei(user,pw,mitpfx,site,tmsrtl,rtno,dev,host)
    dev.close()
    return rsts_output

# launch script with threading - execute for all sites at once - return and print outputs #
def main():
    mitpfx = str(input("Enter /24 transit facing aggregate mitigation route(example:'200.220.20.0/24'): "))
    print('route collection in progress, standby, this can take up to 1 minute to complete...\n')
    adrts = []
    with ThreadPoolExecutor(max_workers=totalsites) as executor:
        futures = [executor.submit(get_routing_data,user,pw,mitpfx,site,cscom,agcom) for site in sites]
        for future in as_completed(futures):
            adrts.append(future.result())
    try:
        adrts_output = '\n'.join(adrts)
        print(dts,'route collection output:\n')
        if re.sub(r'\n','',adrts_output) == '':
            print(dts,'\nno active mitigation agg routes found for {0}\n'.format(mitpfx))
        else:
            print(adrts_output)
    except:
        print(dts,'\nno active mitigation agg routes found for {0}\n'.format(mitpfx))

main()

