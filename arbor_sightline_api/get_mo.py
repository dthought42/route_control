#!/usr/bin/python3.6
import grequests
import requests
import yaml
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import base64
import boto3
import json
import re
import urllib3
import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler, SysLogHandler

logging.getLogger('get_mo.py python3.6')
logging.basicConfig(level=logging.INFO,
        format='[%(asctime)s] - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[SysLogHandler(address='/dev/log'),
                  RotatingFileHandler(filename='logs_prod/get_mo.log',
                                      backupCount=7,
                                      maxBytes=100 * 1024 ** 2)])

urllib3.disable_warnings()
passphrase = 'SANITIZED'.encode()
settings_file = open('/settings/settings.yaml', 'r')
settings = yaml.safe_load(settings_file)
BLOCK_SIZE=16
def trans(key):
    return MD5.new(key).digest()
def passhash(encrypted, passphrase):
    passphrase = trans(passphrase)
    encrypted = base64.b64decode(encrypted)
    IV = encrypted[:BLOCK_SIZE]
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    return aes.decrypt(encrypted[BLOCK_SIZE:])
url = settings['netsvc_acct']['url']
key = settings['netsvc_acct']['aws_key']
settings['netsvc_acct']['aws_secret'] = passhash(settings['netsvc_acct']['aws_secret'],passphrase)
secret = settings['netsvc_acct']['aws_secret']
secret = "".join( chr(x) for x in secret)
settings['netsvc_acct']['atk'] = passhash(settings['netsvc_acct']['atk'],passphrase)
atk = settings['netsvc_acct']['atk']
atk = "".join( chr(x) for x in atk)
s3d = dict(aws_access_key_id=key, aws_secret_access_key=secret)

def upload_json_to_s3(sl_customers, s3d):
    session = boto3.Session(**s3d)
    s3 = session.client('s3')
    response = s3.put_object(Body=(sl_customers), Bucket='sl_customers', Key='sl_customers.json')
    return response

def get_json_config(url, atk): 
    response = requests.get(url, headers={"X-Arbux-APIToken": atk}, verify=False)
    lp = (response.json()['links']['last'])
    lp = int(re.findall(r'(?<=&page=).*',lp)[0])
    p = 1
    url_set = ''
    while p <= lp:
        urli = url + '?page={}'.format(p)
        url_set = url_set + urli + '\n'
        p = p + 1
    urls = [i for i in (url_set.split('\n')) if i]
    rs = (grequests.get(url, headers={"X-Arbux-APIToken": atk}, verify=False) for url in urls)
    response = [i for i in (grequests.map(rs)) if i]
    results = [r.json() for r in response]
    mos = [re.sub(' ','_',ad['attributes']['name']) for dd in results for ad in dd['data'] if ad['attributes'].get('family')=='customer']
    sl_customers = json.dumps(mos)
    return sl_customers

if __name__ == "__main__":
    sl_customers = get_json_config(url, atk)
    response = upload_json_to_s3(sl_customers, s3d)
    logging.getLogger('get_mo.py python3.6').info('sl_customers.json updated - S3 sl_customers - VID: {0}'.format(response['VersionId']))
