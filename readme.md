#BASHETUP FOR NEW SERVERS

mod it out and cut your time down. shamelessly lifted and tweaked from [betweenbrain](https://github.com/betweenbrain/ubuntu-web-server-build-script).

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
Error on logwatch
Script mongo.auth security
Script swapfile
Script tmp folder security
