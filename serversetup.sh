#!/bin/bash
# ================================================================== #
# Ubuntu 14.04 web server build shell script
# ================================================================== #
# Parts copyright (c) 2012 Matt Thomas http://betweenbrain.com &&
# Improved 2016 by Marcus Guttenplan for Ubuntu 14.04 LTS
# This script is licensed under GNU GPL version 2.0 or above
# ================================================================== #
#
#
#
# ================================================================== #
#          Define system specific details in this section            #
# ================================================================== #
#
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

# ================================================================== #
#                      End system specific details                   #
# ================================================================== #
#

echo
echo "System updates and basic setup"
echo "==============================================================="
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo "First things first, let's make sure we have the latest updates."
echo "---------------------------------------------------------------"


# *) Install required packages
# ------------------------------------------------------------------ #
apt-get update
apt-get upgrade
apt-get install -y --force-yes unattended-upgrades iptables curl git nginx-naxsi postgresql libpq-dev build-essential libcurl4-openssl-dev zlib1g-dev


# *) Configure PostgreSQL
# ------------------------------------------------------------------ #
sed -e "s|local *all *postgres .*|local    all         postgres                   trust|g" \
    -e "s|local *all *all .*|local    all         all                   trust|g" \
    -e "s|host *all *all *127.0.0.1/32 .*|host    all         all        127.0.0.1/32           trust|g" \
    -e "s|host *all *all *::1/128 .*|host    all         all        ::1/128           trust|g" \
    -i /etc/postgresql/8.*/main/pg_hba.conf
/etc/init.d/postgresql restart


# *) Configure machine hostname
# ------------------------------------------------------------------ #


echo
echo "Setting the hostname."
# http://library.linode.com/getting-started
echo "---------------------------------------------------------------"
echo
echo

echo "$HOSTNAME" > /etc/hostname
hostname -F /etc/hostname

echo
echo
echo
echo "Updating /etc/hosts."
echo "---------------------------------------------------------------"

mv /etc/hosts /etc/hosts.bak

echo "
127.0.0.1       localhost
$SYSTEMIP       $HOSTNAME.$DOMAIN     $HOSTNAME
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
" >> /etc/hosts

echo
echo
echo
echo "Setting the proper timezone."
echo "---------------------------------------------------------------"

dpkg-reconfigure tzdata

echo
echo
echo
echo "Synchronize the system clock with an NTP server"
echo "---------------------------------------------------------------"

apt-get install -y ntp
echo
echo
echo
echo "Setting the language and charset"
echo "---------------------------------------------------------------"

locale-gen $LANGUAGE.$CHARSET
/usr/sbin/update-locale LANG=$LANGUAGE.$CHARSET


# *) ADD A USER
# ------------------------------------------------------------------ #


echo
echo
echo
echo "Creating new primary user"
echo "---------------------------------------------------------------"

if [ $(id -u) -eq 0 ]; then
  # read -p "Enter username of who can connect via SSH: " USER
  read -s -p "Enter password of user who can connect via SSH: " PASSWORD
  egrep "^$USER" /etc/passwd >/dev/null
  if [ $? -eq 0 ]; then
    echo "$USER exists!"
    exit 1
  else
    pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
    useradd -s /bin/bash -m -d /home/$USER -U -p $pass $USER
    [ $? -eq 0 ] && echo "$USER has been added to system!" || echo "Failed to add a $USER!"
  fi
else
  echo "Only root may add a user to the system"
  exit 2
fi

echo
echo
echo
echo "Adding $USER to sudoers"
echo "---------------------------------------------------------------"

cp /etc/sudoers /etc/sudoers.tmp
chmod 0640 /etc/sudoers.tmp
echo "$USER    ALL=(ALL) ALL" >> /etc/sudoers.tmp
chmod 0440 /etc/sudoers.tmp
mv /etc/sudoers.tmp /etc/sudoers

# *) Manage SSH Keys before updating SSH config
# ------------------------------------------------------------------ #

echo
echo
echo
echo "Adding ssh key"
echo "---------------------------------------------------------------"

mkdir /home/$USER/.ssh
touch /home/$USER/.ssh/authorized_keys
echo $PUBLICKEY >> /home/$USER/.ssh/authorized_keys
chown -R $USER:$USER /home/$USER/.ssh
chmod 700 /home/$USER/.ssh
chmod 600 /home/$USER/.ssh/authorized_keys


# *) Update and Harden SSH
# ------------------------------------------------------------------ #


echo
echo
echo
echo "Change SSH port"
echo "---------------------------------------------------------------"

sed -i "s/Port 22/Port $SSHPORT/g" /etc/ssh/sshd_config

echo
echo
echo
echo "Instruct sshd to listen only on a specific IP address."
echo "---------------------------------------------------------------"
echo

sed -i "s/#ListenAddress 0.0.0.0/ListenAddress $SYSTEMIP/g" /etc/ssh/sshd_config

echo
echo
echo
echo "Ensure that sshd starts after eth0 is up, not just after filesystem"
# http://blog.roberthallam.org/2010/06/sshd-not-running-at-startup/
echo "---------------------------------------------------------------"

sed -i "s/start on filesystem/start on filesystem and net-device-up IFACE=eth0/g" /etc/init/ssh.conf

echo
echo
echo
echo
echo "Disabling root ssh login"
echo "---------------------------------------------------------------"

sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config

echo
echo
echo
echo "Disabling password authentication"
echo "---------------------------------------------------------------"

sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config

echo
echo
echo
echo "Disabling X11 forwarding"
echo "---------------------------------------------------------------"

sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config

echo
echo
echo
echo "Disabling sshd DNS resolution"
echo "---------------------------------------------------------------"

echo "UseDNS no" >> /etc/ssh/sshd_config

echo
echo
echo
echo "Adding users to allowusers"
echo "---------------------------------------------------------------"

echo "AllowUsers $USER" >> /etc/ssh/sshd_config

sed -i "s/#AuthorizedKeysFile/AuthorizedKeysFile/g" /etc/ssh/sshd_config

/etc/init.d/ssh restart


# *) IPTables
# ------------------------------------------------------------------ #

echo
echo
echo
echo "Setting up basic(!) rules for IPTables. Modify as needed, with care :)"
# http://www.thegeekstuff.com/scripts/iptables-rules
# http://wiki.centos.org/HowTos/Network/IPTables
# https://help.ubuntu.com/community/IptablesHowTo
echo "---------------------------------------------------------------"
#
# Flush old rules
iptables -F

# Allow SSH connections on tcp port $SSHPORT
# This is essential when working on remote servers via SSH to prevent locking yourself out of the system
#
iptables -A INPUT -p tcp --dport $SSHPORT -j ACCEPT

# Set default chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Accept packets belonging to established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback access
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow incoming HTTP
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow incoming HTTPS
iptables -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Ping from inside to outside
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Allow packets from internal network to reach external network.
# if eth1 is external, eth0 is internal
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT

# Help prevent DoS attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Log dropped packets
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -I INPUT -m limit --limit 5/min -j LOG --log-prefix "Iptables Dropped Packet: " --log-level 7
iptables -A LOGGING -j DROP

# Create the script to load the rules
echo "#!/bin/sh
iptables-restore < /etc/iptables.rules
" > /etc/network/if-pre-up.d/iptablesload

# Create the script to save current rules
echo "#!/bin/sh
iptables-save > /etc/iptables.rules
if [ -f /etc/iptables.downrules ]; then
   iptables-restore < /etc/iptables.downrules
fi
" > /etc/network/if-post-down.d/iptablessave

# Ensure they are executible
chmod +x /etc/network/if-post-down.d/iptablessave
chmod +x /etc/network/if-pre-up.d/iptablesload
#
/etc/init.d/networking restart
#
echo
echo
echo
echo "Establish IPTables logging, and rotation of logs"
# http://ubuntuforums.org/showthread.php?t=668148
# https://wiki.ubuntu.com/LucidLynx/ReleaseNotes#line-178
echo "---------------------------------------------------------------"
#
echo "#IPTables logging
kern.debug;kern.info /var/log/firewall.log
" > /etc/rsyslog.d/firewall.conf
#
/etc/init.d/rsyslog restart
#
mkdir /var/log/old/
#
echo "/var/log/firewall.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 640 syslog adm
    olddir /var/log/old/
}
" > /etc/logrotate.d/firewall
#
echo
echo
echo
echo "Adding a bit of color and formatting to the command prompt"
# http://ubuntuforums.org/showthread.php?t=810590
echo "---------------------------------------------------------------"
#
echo '
export PS1="${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
' >> /home/$USER/.bashrc
source /home/$USER/.bashrc


# *) Server Security and Hardening
# ------------------------------------------------------------------ #


echo
echo
echo
echo "Linux kernel hardening"
# http://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
echo "--------------------------------------------------------------"
#
cp /etc/sysctl.conf /etc/sysctl.conf.bak
#
sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_echo_ignore_broadcasts = 1/net.ipv4.icmp_echo_ignore_broadcasts = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_ignore_bogus_error_responses = 1/net.ipv4.icmp_ignore_bogus_error_responses = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/g" /etc/sysctl.conf
#
echo "#
# Controls the use of TCP syncookies
net.ipv4.tcp_synack_retries = 2
# Increasing free memory
vm.min_free_kbytes = 16384
" >> /etc/sysctl.conf
#
sysctl -p
#
echo
echo
echo
echo "Installing and configuring logwatch for log monitoring"
# https://help.ubuntu.com/community/Logwatch
echo "--------------------------------------------------------------"
#
aptitude -y install logwatch
mkdir /var/cache/logwatch
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/
#
cp /usr/share/logwatch/default.conf/logfiles/http.conf to /etc/logwatch/conf/logfiles
#
echo "
# Log files for $DOMAIN
LogFile = /home/$USER/public_html/$DOMAIN/log/access.log
LogFile = /home/$USER/public_html/$DOMAIN/log/error.log
LogFile = /home/$USER/public_html/$DOMAIN/log/ssl_error.log
LogFile = /home/$USER/public_html/$DOMAIN/log/ssl_access.log
" >> /etc/logwatch/conf/logfiles/http.conf


# *) Dev Tools
# ------------------------------------------------------------------ #

echo
echo
echo
echo "Verify and Download NodeJS"

curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
apt-get install -y nodejs

echo
echo
echo
echo "Verify and Download MongoDB"

apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

#update and reload
apt-get update
apt-get install mongodb-org


# *) ALMOST THERE!!!!!
# ------------------------------------------------------------------ #


echo
echo
echo
echo "One final hurrah"
echo "--------------------------------------------------------------"
echo

apt-get update
apt-get upgrade

echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo "==============================================================="
echo
echo "All done!"
echo
echo "If you are confident that all went well, reboot this puppy and play."
echo
echo "If not, now is your (last?) chance to fix things."
echo
echo "==============================================================="

