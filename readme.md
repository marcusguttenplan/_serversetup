#BASHETUP FOR NEW SERVERS

Quickly spin up secure configs for sparkly new Ubuntu 14.04 servers. Mod it out and cut down startup time. Shamelessly lifted and tweaked from [betweenbrain](https://github.com/betweenbrain/ubuntu-web-server-build-script). Still throwing some minor errors.

###USAGE

edit the globals at the top with a name for your host, an IP for services to use, a FQDN, ports, a username to generate, and public key:
```
HOSTNAME=
SYSTEMIP=
DOMAIN=
LANGUAGE=
CHARSET=
SSHPORT=
IGNOREIP=
USER=
ADMINEMAIL=
PUBLICKEY="ssh-rsa ... foo@bar.com"
```

from your local machine, after spinning up a new server, copy script
```
scp serversetup.sh user@host:~/serversetup.sh
```

from remote machine, run script as `root`
```
bash serversetup.sh
```

or, if you'd like to configure OpenVPN once initial install is complete, run script
```
bash serversetup_vpn.sh
```

this will configure the server to push tunnel routes to clients and NAT them.
to add additional vpn profiles for clients, run
```
bash openvpn-install-helper.sh
```

the script will update system, upgrade packages, install tools for development (postgres, mongo, nodejs, git, etc), harden security, and generate a new user. it's fast.

#### IPtables Blacklist

```
mkdir -p /etc/ipset-blacklist
```
```
cp ipset-blacklist/ipset-blacklist.conf /etc/ipset-blacklist/ipset-blacklist.conf
```
```
cp ipset-blacklist/ip-blacklist-custom.list /etc/ipset-blacklist/ip-blacklist-custom.list
```

Update, load updated `ipset` list with `restore`, create `iptables` rule:
```
bash ipset-blacklist/update-blacklist.sh
```
```
ipset restore < /etc/ipset-blacklist/ip-blacklist.restore
```
```
iptables -I INPUT 1 -m set --match-set blacklist src -j DROP
```

`iptables-persistent` will persist these rules. 

#### dotfiles

```
cp _dotfiles/bashrc ~/.bashrc && cp _dotfiles/bash_profile ~/.bash_profile
source ~/.bash_profile
```

#####TODO
* Fix error on `logwatch`
* Script `mongo --auth` security
* Script `swapfile`
* Script `tmp` folder security
\\
