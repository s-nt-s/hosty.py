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


class MyHosts:
    HOSTS_FILE = "/etc/hosts"
    DEBUG_FILE = "hosts.txt"
    CONFIG_BEGIN = "# HOSTY CONFIG BEGIN"
    CONFIG_END = "# HOSTY CONFIG END"
    DOMANINS_BEGIN = "# HOSTY DOMANINS BEGIN"
    DOMANINS_END = "# HOSTY DOMANINS END"
    re_hosts = re.compile(r"^\s*\d+\.\d+.\d+.\d+[ \t]+([^#\n]+)", re.MULTILINE)
    re_rules = re.compile(
        r"^\|\|([a-z][a-z0-9\-_.]+\.[a-z]+)\^\s*$", re.MULTILINE)
    re_dom = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", re.IGNORECASE)

    def __init__(self, fl=None):
        self.file = (fl or MyHosts.HOSTS_FILE)

    def _get_config(self):
        yml = None
        with open(self.file, "r") as f:
            for l in f.readlines():
                l = l.strip()
                if not l.startswith("#"):
                    continue
                if l == MyHosts.CONFIG_END:
                    return "\n".join(yml)
                if yml is not None:
                    yml.append(l[1:])
                elif l == MyHosts.CONFIG_BEGIN:
                    yml = []

    def _to_bunch(self, yml, check_default=False):
        yml = yaml.load(yml, Loader=yaml.FullLoader)
        if check_default:
            dfl = self._to_bunch(DEFAULT)
            for k, v in dict(dfl).items():
                if k in yml:
                    continue
                if isinstance(v, list):
                    yml[k] = []
                else:
                    yml[k] = v
        yml = Bunch(**yml)
        return yml

    def get_config(self):
        yml = self._get_config()
        if yml is not None:
            return self._to_bunch(yml, check_default=True)

        yml = self._to_bunch(DEFAULT)
        print("HOSTY CONFIG not found")
        print("Setting default...")
        isB = self.isLastBlank()
        with open(self.file, "a") as f:
            if not isB:
                f.write("\n")
            f.write(MyHosts.CONFIG_BEGIN)
            for l in DEFAULT.strip().split("\n"):
                f.write("\n# "+l)
            f.write("\n"+MyHosts.CONFIG_END+"\n")
        return yml

    def rewrite(self, ini, fin, *new_lines, rewrite=None):
        isB = False
        with open(self.file, 'r+') as f:
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

    def isLastBlank(self):
        with open(self.file, 'r') as f:
            ln = f.readlines()[-1].strip()
            return ln == ""

    @property
    def original(self):
        original = ''
        flag = True
        with open(self.file, "r") as f:
            for ln in f.readlines():
                l = ln.strip()
                if l in (MyHosts.CONFIG_BEGIN, MyHosts.DOMANINS_BEGIN):
                    flag = False
                    continue
                if l in (MyHosts.CONFIG_END, MyHosts.DOMANINS_END):
                    flag = True
                    continue
                if flag:
                    original = original + ln
        return original

    @property
    def original_doms(self):
        for l in MyHosts.re_hosts.findall(self.original):
            for i in l.strip().split():
                if MyHosts.re_dom.match(i):
                    yield i

    def restore(self):
        self.rewrite(MyHosts.DOMANINS_BEGIN, MyHosts.DOMANINS_END)
        self.rewrite(MyHosts.CONFIG_BEGIN, MyHosts.CONFIG_END)

    def on(self):
        self.rewrite(MyHosts.DOMANINS_BEGIN, MyHosts.DOMANINS_END,
                     rewrite=lambda l: l[1:] if l.startswith("#") else l)

    def off(self):
        self.rewrite(MyHosts.DOMANINS_BEGIN, MyHosts.DOMANINS_END, rewrite=lambda l: l if (
            l.startswith("#") or not l.strip()) else "#" + l)

    def write_doms(self, ip, *doms):
        doms=sorted(doms, key=lambda x: tuple(reversed(x.split("."))))
        self.rewrite(MyHosts.DOMANINS_BEGIN, MyHosts.DOMANINS_END,
                     *(ip+" "+d for d in doms))


def check_file(fl):
    if not os.path.isfile(fl):
        return -3
    if not os.access(fl, os.R_OK):
        return -2
    if not os.access(fl, os.W_OK):
        return -1
    return 1


def get_text(fl, st):
    if st == -3:
        return fl+" doesn't exist"
    if st == -2:
        return fl+" can't be read"
    if st == -1:
        return fl+" can't be overwritten"

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
                yield read_file(fl)
        elif url.endswith(".zip"):
            # TODO
            pass
        else:
            ct = r.headers.get('content-type')
            if "text/plain" in ct.lower():
                yield r.text

def read_doms_from_url(*urls, find):
    for text in read_url(*urls):
        for l in find.findall(text):
            for i in l.strip().split():
                if MyHosts.re_dom.match(i):
                    yield i

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Ad-blocking by '+MyHosts.HOSTS_FILE)
    parser.add_argument('--restore', action='store_true',
                        help='Remove ad-blocking config and rules')
    parser.add_argument('--debug', action='store_true',
                        help="Create local example ("+MyHosts.DEBUG_FILE+") instead overwrite "+MyHosts.HOSTS_FILE)
    parser.add_argument('--off', action='store_true',
                        help="Deactivate 'HOSTY DOMANINS' section in "+MyHosts.HOSTS_FILE)
    parser.add_argument('--on', action='store_true',
                        help="Reactive 'HOSTY DOMANINS' section in "+MyHosts.HOSTS_FILE)
    parser.add_argument('--no-verify', action='store_true',
                        help="No verify SSL")
    parser.add_argument('--ip', default="0.0.0.0",
                        help="IP to redirect (0.0.0.0 by default)")
    args = parser.parse_args()

    is_HOSTS_FILE = check_file(MyHosts.HOSTS_FILE)
    is_DEBUG_FILE = check_file(MyHosts.DEBUG_FILE)

    if not args.debug and is_HOSTS_FILE == -1:
        print(get_text(MyHosts.HOSTS_FILE, is_HOSTS_FILE))
        print("Changing to debug mode... (result will store in %s)" %
              MyHosts.DEBUG_FILE)
        args.debug = True
    if not args.debug and is_HOSTS_FILE not in (-1, 1):
        sys.exit(get_text(MyHosts.HOSTS_FILE, is_HOSTS_FILE))
    if args.debug and is_DEBUG_FILE != 1:
        print(get_text(MyHosts.DEBUG_FILE, is_DEBUG_FILE))
        if is_HOSTS_FILE in (-3, -2):
            sys.exit("Can't copy from %s to %s" %
                     (MyHosts.HOSTS_FILE, MyHosts.DEBUG_FILE))
        print("cp %s %s" % (MyHosts.HOSTS_FILE, MyHosts.DEBUG_FILE))
        shutil.copy(MyHosts.HOSTS_FILE, MyHosts.DEBUG_FILE)

    myHosts = MyHosts(MyHosts.DEBUG_FILE if args.debug else MyHosts.HOSTS_FILE)

    if args.restore:
        myHosts.restore()
        sys.exit()

    if args.off:
        myHosts.off()
        sys.exit()

    if args.on:
        myHosts.on()
        sys.exit()

    cfn = myHosts.get_config()
    cfn.whitelist = set(cfn.whitelist).union(myHosts.original_doms).union((
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

    rst = {
        "blacklist":cfn.blacklist
    }

    for url in sorted(cfn.hosts):
        rst[url] = set(read_doms_from_url(url, find=MyHosts.re_hosts)) - cfn.whitelist

    for url in sorted(cfn.rules):
        rst[url] = set(read_doms_from_url(url, find=MyHosts.re_rules)) - cfn.whitelist

    rst = {k:v for k,v in rst.items() if v}

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

    myHosts.write_doms(args.ip, *doms)
