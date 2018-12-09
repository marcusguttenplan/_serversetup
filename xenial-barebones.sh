#!/bin/bash
# ================================================================== #
# Ubuntu 14.04 web server build shell script
# ================================================================== #
# Parts copyright (c) 2012 Matt Thomas http://betweenbrain.com &&
# Improved 2016 by Marcus Guttenplan for Ubuntu 14.04 LTS
# This script is licensed under GNU GPL version 2.0 or above
# ================================================================== #


SYSTEMIP=138.68.17.28
SSHPORT=333
USER=worker
PUBLICKEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDEw1ln3lKs6QmXN72cbfrpRmMPf4gSmNAtOYTCzDQFFYC6ZN62K0f1VkVmxufbKXq7uwVwKb83rY+WE5a2rin10zbK7J+/sGjq5kbmc6UncCj7aA44PeDnwKRKSN8NYUaOoLEH7puMhscdrIzl3SOGMaFvFrRpo0lt4W1ufDjyUK4NwizPGK5flWOPkwrR1m9LcMnLljmr28tKVPaYh+h/kOrJc9pc39WWteO7qKVTebGYL3CWlBGlt8wSdMSoJNLYPmW4lekDbvbYUAeyKdK1Q+rmEvG1z6lw+NXC0Qe/kBlTgSM8vj8BmSvC+wLDV0/mm3eaC3wVe+nwgPHVH6yYib6bOoydyeWHBrUscBfGHB/NrLHRgCBbqdnqZh9UT14p5OxeSkNCB/xS8CDHIrlwjh2vd8/yzAfugNkAfwo0G2kqeeVKXnj727lC0++Hmf6Iq4W444ZqCk1awsaq6XBvGcyOGfAlD2GPM5WU7awo1GmphR/RgsVGB6NQXkZ8PnGy3ltd7fWDRaXDUCCWeFpeFRXHmsouWKEqgc1kVJOAGmGk4Roq6wLdowog/EAlGkWYZiFRNxCOCpKcU1yOpQQTICs18uhEQ2L9PzQv3P3cr7sB0cX5A1YpA0fLcvH7CfCaUx0DBA+6zvPeoWvyiWJ9E6+Cm02H1xMsU2zfysYDGQ== marcusguttenplan@marcbook"


##
##
## INSTALL PACKAGES
##
##

apt-get install -y pngcrush libjpeg-progs gifsicle



# *) ADD A USER
# ------------------------------------------------------------------ #


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
echo "Adding users to allowusers"
echo "---------------------------------------------------------------"

echo "\nAllowUsers $USER" >> /etc/ssh/sshd_config

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
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Accept packets belonging to established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback access
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Ping from inside to outside
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Allow packets from internal network to reach external network.
# if eth1 is external, eth0 is internal
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT

# Help prevent DoS attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Make sure DNS doesn;t ever get locked out
# iptables -A INPUT -p udp --dport 53 -s 8.8.8.8 -j ACCEPT
# iptables -A INPUT -p tcp --dport 53 -s 8.8.8.8 -j ACCEPT
# iptables -A INPUT -p tcp --dport 53 -s 8.8.4.4 -j ACCEPT
# iptables -A INPUT -p udp --dport 53 -s 8.8.4.4 -j ACCEPT

# Log dropped packets
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -I INPUT -m limit --limit 5/min -j LOG --log-prefix "Iptables Dropped Packet: " --log-level 7
iptables -A LOGGING -j DROP

#
/etc/init.d/networking restart
#
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
