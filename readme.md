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
sh serversetup.sh
```

the script will update system, upgrade packages, install tools for development (postgres, mongo, nodejs, git, etc), harden security, and generate a new user. it's fast.

#####TODO
-Fix error on `logwatch`
-Script `mongo --auth` security
-Script `swapfile`
-Script `tmp` folder security
-Script `OpenVPN` setup
