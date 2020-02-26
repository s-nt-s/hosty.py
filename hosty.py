#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import sys
import tempfile
from glob import glob
from urllib.parse import urlparse

import py7zr
import requests
import urllib3
import yaml
from bunch import Bunch

urllib3.disable_warnings()

HOSTS_FILE = "/etc/hosts"
DEBUG_FILE = "hosts.txt"

parser = argparse.ArgumentParser(description='Ad-blocking by '+HOSTS_FILE)
parser.add_argument('--restore', action='store_true',
                    help='Remove ad-blocking config and rules')
parser.add_argument('--debug', action='store_true',
                    help="Create local example (hosts.txt) instead overwrite "+HOSTS_FILE)
parser.add_argument('--off', action='store_true',
                    help="Deactivate 'HOSTY DOMANINS' section in "+HOSTS_FILE)
parser.add_argument('--on', action='store_true',
                    help="Reactive 'HOSTY DOMANINS' section in "+HOSTS_FILE)
parser.add_argument('--no-verify', action='store_true',
                    help="No verify SSL")
parser.add_argument('--ip', default="0.0.0.0", help="IP to redirect (0.0.0.0 by default)")
args = parser.parse_args()


def check_file(fl):
    if not os.path.isfile(fl):
        return -3
    if not os.access(fl, os.R_OK):
        return -2
    if not os.access(fl, os.W_OK):
        return -1
    return 1

    #print("Changing to debug mode... (result will store in hosts.txt)")
    args.debug = True


def get_text(fl, st):
    if st == -3:
        return fl+" doesn't exist"
    if st == -2:
        return fl+" can't be read"
    if st == -1:
        return fl+" can't be overwritten"


is_HOSTS_FILE = check_file(HOSTS_FILE)
is_DEBUG_FILE = check_file(DEBUG_FILE)

if not args.debug and is_HOSTS_FILE == -1:
    print(get_text(HOSTS_FILE, is_HOSTS_FILE))
    print("Changing to debug mode... (result will store in %s)" % DEBUG_FILE)
    args.debug = True
if not args.debug and is_HOSTS_FILE not in (-1, 1):
    sys.exit(get_text(HOSTS_FILE, is_HOSTS_FILE))
if args.debug and is_DEBUG_FILE != 1:
    print(get_text(DEBUG_FILE, is_DEBUG_FILE))
    if is_HOSTS_FILE in (-3, -2):
        sys.exit("Can't copy from %s to %s" % (HOSTS_FILE, DEBUG_FILE))
    print("cp %s %s" % (HOSTS_FILE, DEBUG_FILE))
    shutil.copy(HOSTS_FILE, DEBUG_FILE)

if args.debug:
    HOSTS_FILE = DEBUG_FILE

CONFIG_BEGIN = "# HOSTY CONFIG BEGIN"
CONFIG_END = "# HOSTY CONFIG END"
DOMANINS_BEGIN = "# HOSTY DOMANINS BEGIN"
DOMANINS_END = "# HOSTY DOMANINS END"

DEFAULT = '''
# Add ad-blocking hosts files in this array
hosts:
- "http://adaway.org/hosts.txt"
- "http://winhelp2002.mvps.org/hosts.txt"
- "http://hosts-file.net/ad_servers.asp"
- "http://someonewhocares.org/hosts/hosts"
- "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
- "https://raw.githubusercontent.com/jorgicio/publicidad-chile/master/hosts.txt"
- "https://raw.githubusercontent.com/astrolince/hosty/master/hostyhosts.txt"
- "http://rlwpx.free.fr/WPFF/hpub.7z"
- "http://rlwpx.free.fr/WPFF/hrsk.7z"
- "https://www.malwaredomainlist.com/hostslist/hosts.txt"
- "https://www.hostsfile.org/Downloads/hosts.txt"
# You can find more in https://github.com/AdAway/AdAway/wiki/HostsSources
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
whitelist:
- fake_example_of_whitelist_or_blacklist.com
blacklist:
- fake_example_of_whitelist_or_blacklist.com
'''

re_hosts = re.compile(r"^\s*\d+\.\d+.\d+.\d+\s+([^#\s]+)", re.MULTILINE)
re_rules = re.compile(r"^\|\|([a-z][a-z0-9\-_.]+\.[a-z]+)\^\s*$", re.MULTILINE)


def read_config():
    yml = None
    with open(HOSTS_FILE, "r") as f:
        for l in f.readlines():
            l = l.strip()
            if not l.startswith("#"):
                continue
            if l == CONFIG_END:
                return "\n".join(yml)
            if yml is not None:
                yml.append(l[1:])
            elif l == CONFIG_BEGIN:
                yml = []


def to_bunch(yml, check_default=False):
    yml = yaml.load(yml, Loader=yaml.FullLoader)
    if check_default:
        dfl = to_bunch(DEFAULT)
        for k, v in dict(dfl).items():
            if k in yml:
                continue
            if isinstance(v, list):
                yml[k] = []
            else:
                yml[k] = v
    yml = Bunch(**yml)
    return yml


def get_config():
    yml = read_config()
    if yml is not None:
        return to_bunch(yml, check_default=True)

    yml = to_bunch(DEFAULT)
    print("HOSTY CONFIG not found")
    print("Setting default...")
    isB = isBlank()
    with open(HOSTS_FILE, "a") as f:
        if not isB:
            f.write("\n")
        f.write(CONFIG_BEGIN)
        for l in DEFAULT.strip().split("\n"):
            f.write("\n# "+l)
        f.write("\n"+CONFIG_END+"\n")
    return yml


def split_text(text, find=None):
    if find is None:
        lns = text.split("\n")
    else:
        lns = find.findall(text)
    for l in lns:
        l = l.strip()
        if l:
            yield l


def read_file(fl):
    try:
        with open(fl, "r") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(fl, "rb") as f:
            return f.read().decode('utf-8', 'ignore')


def read_url(*urls, find=None):
    for url in urls:
        try:
            r = requests.get(url, verify=not(args.no_verify))
        except requests.exceptions.SSLError:
            print("SSL", url)
            continue
        if r.status_code != 200:
            print(r.status_code, url)
            continue
        print("   ", url)
        if url.endswith(".7z"):
            tmp = tempfile.TemporaryDirectory()
            fl = tmp.name+"/fl.7z"
            with open(fl, "wb") as f:
                f.write(r.content)
            out = tmp.name+"/out"
            os.mkdir(out)
            arch = py7zr.SevenZipFile(fl, mode='r')
            arch.extractall(path=out)
            arch.close()
            for fl in sorted(glob(out+"/*")):
                for l in split_text(read_file(fl), find=find):
                    yield l
        elif url.endswith(".zip"):
            # TODO
            pass
        else:
            ct = r.headers.get('content-type')
            if "text/plain" in ct.lower():
                for l in split_text(r.text, find=find):
                    yield l


def write_hosts(*new_lines, ini=DOMANINS_BEGIN, fin=DOMANINS_END, rewrite=None):
    isB = False
    with open(HOSTS_FILE, 'r+') as f:
        lines = f.readlines()
        f.seek(0)
        flag = False
        for ln in lines:
            l = ln.strip()
            if flag:
                if rewrite is not None:
                    nw = ln if l in (fin, ini) else rewrite(ln)
                    if not nw.endswith("\n"):
                        nw = nw + "\n"
                    f.write(nw)
                continue
            if l in (ini, fin):
                flag = (l == ini)
                if rewrite is not None:
                    f.write(ln)
                continue
            f.write(ln)
            isB = (l == "")
        if new_lines:
            if not isB:
                f.write("\n")
            f.write(ini+"\n")
            for l in new_lines:
                f.write(l+"\n")
            f.write(fin+"\n")
        f.truncate()


def isBlank():
    with open(HOSTS_FILE, 'r') as f:
        ln = f.readlines()[-1].strip()
        return ln == ""


if args.restore:
    write_hosts(ini=DOMANINS_BEGIN, fin=DOMANINS_END)
    write_hosts(ini=CONFIG_BEGIN, fin=CONFIG_END)
    sys.exit()

if args.off:
    write_hosts(ini=DOMANINS_BEGIN, fin=DOMANINS_END, rewrite=lambda l: l if (
        l.startswith("#") or not l.strip()) else "#" + l)
    sys.exit()

if args.on:
    write_hosts(ini=DOMANINS_BEGIN, fin=DOMANINS_END,
                rewrite=lambda l: l[1:] if l.startswith("#") else l)
    sys.exit()

cfn = get_config()
cfn.whitelist = set(cfn.whitelist).union((
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters"
))
for url in cfn.hosts + cfn.rules:
    p = urlparse(url)
    cfn.whitelist.add(p.netloc)

cfn.blacklist = set(cfn.blacklist) - cfn.whitelist

rst = {}

for url in sorted(cfn.hosts):
    doms = set(read_url(url, find=re_hosts)) - cfn.whitelist
    if doms:
        rst[url] = doms

for url in sorted(cfn.rules):
    doms = set(read_url(url, find=re_rules)) - cfn.whitelist
    if doms:
        rst[url] = doms

if cfn.blacklist:
    rst["blacklist"] = cfn.blacklist

if not rst:
    sys.exit("\nDomains not founds. Abort!")

print("\nDomains founds:\n")
doms = set()
debu = []
rst = sorted(rst.items(), key=lambda kv: (-len(kv[1]), kv[0]))


for url, dom in rst:
    sz = len(doms)
    doms = doms.union(dom)
    debu.append((url, len(dom), len(doms)-sz))

m_tot = max(i[1] for i in debu)
m_dif = max(i[2] for i in debu)
m_dif = len(str(m_dif))
s_dif = "%"+str(m_dif)+"s"
line = "%"+str(len(str(m_tot)))+"s %s %s"

for i, (url, tot, dif) in enumerate(debu):
    if len(debu) == 1:
        dif = "/******/"
    elif i == 0:
        dif = (" "*(m_dif+3))
    else:
        dif = "[+" + (s_dif % dif) + "]"
    l = line % (tot, dif, url)
    l = l.replace("/******/ ", "")
    print(l)

if len(debu) > 1:
    print("Total:", len(doms))

write_hosts(*(args.ip+" "+d for d in sorted(doms)))
