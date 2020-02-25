#!/usr/bin/env python3

import requests
from bunch import Bunch
import yaml

CONFIG_BEGIN="# HOSTY CONFIG BEGIN"
CONFIG_END="# HOSTY CONFIG END"

DEFAULT='''
# Add ad-blocking hosts files in this array
hosts:
- "http://adaway.org/hosts.txt"
- "http://winhelp2002.mvps.org/hosts.txt"
- "http://hosts-file.net/ad_servers.asp"
- "http://someonewhocares.org/hosts/hosts"
- "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
- "https://raw.githubusercontent.com/jorgicio/publicidad-chile/master/hosts.txt"
- "https://raw.githubusercontent.com/astrolince/hosty/master/hostyhosts.txt"
# Add AdBlock Plus rules files in this array
rules:
- "https://easylist-downloads.adblockplus.org/easylist.txt"
- "https://data.getadblock.com/filters/adblock_custom.txt"
- "https://easylist-downloads.adblockplus.org/easyprivacy.txt"
- "http://abp.mozilla-hispano.org/nauscopio/filtros.txt"
- "https://easylist-downloads.adblockplus.org/malwaredomains_full.txt"
- "https://adguard.com/en/filter-rules.html?id=2"
- "https://adguard.com/en/filter-rules.html?id=3"
- "https://adguard.com/en/filter-rules.html?id=9"
# Set IP to redirect
ip: "0.0.0.0"
whitelist:
- example_of_domain_to_manual_exclude.com
blacklist:
- example_of_domain_to_manual_include.com
'''

def read_config():
    yml=None
    with open("/etc/hosts", "r") as f:
        for l in f.readlines():
            l = l.strip()
            if not l.startswith("#"):
                continue
            if l == CONFIG_END:
                return "\n".join(yml)
            if yml is not None:
                yml.append(l[1:])
            elif l == CONFIG_BEGIN:
                yml=[]

def to_bunch(yml, check_default=False):
    yml = yaml.load(yml, Loader=yaml.FullLoader)
    if check_default:
        dfl = to_bunch(DEFAULT)
        for k, v in dict(dfl).items():
            if k in yml:
                continue
            if isinstance(v, list):
                yml[k]=[]
            else:
                yml[k]=v
    yml = Bunch(**yml)
    return yml
        

def get_config():
    yml = read_config()
    if yml is not None:
        return to_bunch(yml, check_default=True)

    yml = to_bunch(DEFAULT)
    print("HOSTY CONFIG not found")
    print("Setting default...")
    with open("/etc/hosts", "a") as f:
        f.write("\n"+CONFIG_BEGIN)
        for l in DEFAULT.strip().split("\n"):
            f.write("\n# "+l)
        f.write("\n"+CONFIG_END+"\n")
    return yml

cfn = get_config()
