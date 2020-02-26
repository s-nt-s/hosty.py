
```console
$ pip3 install -r requirements.txt
$ ./hosty.py --help
usage: hosty.py [-h] [--restore] [--debug] [--off] [--on] [--no-verify]
                [--ip IP]

Ad-blocking by /etc/hosts

optional arguments:
  -h, --help   show this help message and exit
  --restore    Remove ad-blocking config and rules
  --debug      Create local example (hosts.txt) instead overwrite /etc/hosts
  --off        Deactivate 'HOSTY DOMANINS' section in /etc/hosts
  --on         Reactive 'HOSTY DOMANINS' section in /etc/hosts
  --no-verify  No verify SSL
  --ip IP      IP to redirect (0.0.0.0 by default)
```
