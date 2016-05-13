#INITIAL STEPS
##ubuntu 14.04

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get autoremove
sudo apt-get autoclean
```

###adduser

```
adduser worker
```

```
gpasswd -a worker sudo
```

lockdown `su`
```
dpkg-statoverride --update --add root sudo 4750 /bin/su
```

unattended-upgrades, for sec
```
sudo apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

###ssh-keygen

```
mkdir .ssh
chmod 700 .ssh
```

copy keys into `authorized keys`
```
chmod 600 .ssh/authorized_keys
```

repeat for user
```
mkdir /home/worker/.ssh
chmod 700 .ssh
touch authorized_keys
```

copy keys <b>TODO</b>b> automate this
```
chmod 600 .ssh/authorized_keys
```

```
nano /etc/ssh/sshd_config
```

```
# Package generated configuration file
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 1024

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	~/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
PasswordAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM no

AllowUsers worker

```

```
service ssh restart
```


###hardening

log rollups
```
apt-get install logwatch
```

Make it show output from the last week by editing /etc/cron.weekly/00logwatch and adding --range 'between -7 days and -1 days' to the end of the /usr/sbin/logwatch command.
```
mv /etc/cron.daily/00logwatch /etc/cron.weekly/
```


process accounting
```
apt-get install acct
touch /var/log/wtmp
```

####swap file

```
sudo fallocate -l 4G /swapfile
```

```
sudo chmod 600 /swapfile
```

```
sudo mkswap /swapfile
```

```
sudo swapon /swapfile
```

```
sudo sh -c 'echo "/swapfile none swap sw 0 0" >> /etc/fstab'
```

####secure tmp folders
```
sudo nano /etc/fstab
```

```
tmpfs     /run/shm    tmpfs     ro,noexec,nosuid        0       0
```

```
sudo mount -a
```

```
sudo dd if=/dev/zero of=/usr/tmpDSK bs=1024 count=1024000
sudo mkfs.ext4 /usr/tmpDSK
```

```
sudo cp -avr /tmp /tmpbackup
```

```
sudo mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDSK /tmp
sudo chmod 1777 /tmp
```

```
sudo cp -avr /tmpbackup/* /tmp/
sudo rm -rf /tmpbackup
```

```
sudo nano /etc/fstab
```

```
/usr/tmpDSK /tmp tmpfs loop,nosuid,noexec,rw 0 0
```

```
sudo mount -a
```

```
sudo mv /var/tmp /var/tmpold
sudo ln -s /tmp /var/tmp
sudo cp -avr /var/tmpold/* /tmp/
```

####process limits

```
sudo nano /etc/security/limits.conf
```

```
user1 hard nproc 100
@group1 hard nproc 20
```

###devenv

```
sudo apt-get git build-essential openssl libssl-dev pkg-config
```

####node

```
curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
sudo apt-get install -y nodejs
```

install global dev tools
```
sudo npm install -g bower grunt-cli
```

####mongo

add key
```
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
```

add to sources
```
echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list
```

reload sources
```
sudo apt-get update
```

```
sudo apt-get install mongodb-org
```

```
sudo service mongod start
sudo service mongod stop
sudo service mongod restart
```

connect to mongo shell, create users
```
use admin
db.createUser(
  {
    user: "siteUserAdmin",
    pwd: "password",
    roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
  }
)

db.createUser(
    {
      user: "reportsUser",
      pwd: "12345678",
      roles: [
         { role: "read", db: "" },
         { role: "read", db: "" },
         { role: "read", db: "" },
         { role: "readWrite", db: "" }
      ]
    }
)
```

reload with auth enabled
```
mongod --auth --config /etc/mongodb/mongodb.conf
```

```
db.auth("","")
```

```
mongoimport --username --password --db  --collections  --type csv --headerline --file
```

####nginx

```
sudo apt-get install nginx-naxsi
```

autostart on reboot
```
sudo update-rc.d nginx defaults
```

```
user www-data;
worker_processes 1;
worker_priority	15;
pid /run/nginx.pid;

events {
	worker_connections 512;
	# multi_accept on;
}

http {
	#Server Header
	more_set_headers "Server: boomboom";

	# Let NGINX get the real client IP for its access logs
	set_real_ip_from 127.0.0.1;
	real_ip_header X-Forwarded-For;

	# Security Settings
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	add_header X-Frame-Options SAMEORIGIN;
	add_header X-Content-Type-Options nosniff;
	add_header X-XSS-Protection "1; mode=block";
	#add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com; img-src 'self'; style-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-src 'none'; object-src 'none'";
	#add_header Content-Security-Policy "default-src 'self'; https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; style-src https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src 'none'";
	etag off;
	## Size Limits
	#client_body_buffer_size   8k;
	#client_header_buffer_size 1k;
	#client_max_body_size      1m;
	#large_client_header_buffers 4 4k/8k;

	server_tokens off;

	# Timeouts, do not keep connections open longer then necessary to reduce
	# resource usage and deny Slowloris type attacks.
	client_body_timeout      5s; # maximum time between packets the client can pause when sending nginx any data
	client_header_timeout    5s; # maximum time the client has to send the entire header to nginx
	#keepalive_timeout       75s; # timeout which a single keep-alive client connection will stay open
	send_timeout            15s; # maximum time between packets nginx is allowed to pause when sending the client data

	keepalive_requests        50;  # number of requests per connection, does not affect SPDY
	keepalive_disable         none; # allow all browsers to use keepalive connections
	max_ranges                1; # allow a single range header for resumed downloads and to stop large range header DoS attacks
	msie_padding              off;
	open_file_cache           max=1000 inactive=2h;
	open_file_cache_errors    on;
	open_file_cache_min_uses  1;
	open_file_cache_valid     1h;
	output_buffers            1 512;
	postpone_output           1440;   # postpone sends to match our machine's MSS
	read_ahead                512K;   # kernel read head set to the output_buffers
	recursive_error_pages     on;
	reset_timedout_connection on;  # reset timed out connections freeing ram

	#tcp_nodelay               on; # Nagle buffering algorithm, used for keepalive only
	#tcp_nopush                off;

	server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;
	gzip_disable "msie6";

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# nginx-naxsi config
	##
	# Uncomment it if you installed nginx-naxsi
	##

	#include /etc/nginx/naxsi_core.rules;

	##
	# nginx-passenger config
	##
	# Uncomment it if you installed nginx-passenger
	##

	#passenger_root /usr;
	#passenger_ruby /usr/bin/ruby;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```

```
sudo mkdir -p /var/www/example.com/html
sudo mkdir -p /var/www/test.com/html
```

```
sudo chown -R $USER:$USER /var/www/example.com/html
sudo chown -R $USER:$USER /var/www/test.com/html
```

```
sudo chmod -R 755 /var/www
```

```
sudo cp /etc/nginx/sites-available/. /etc/nginx/sites-available/.
```

```
server {
    listen 80;
    listen [::]:80;

    server_name <>; # Replace with your domain

    root /var/www/;
    index index.html index.htm;
    error_page 401 403 404 /404.html;
    client_max_body_size 10G;

    location / {
        #proxy_pass http://localhost:2836/;
        #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #proxy_set_header Host $http_host;
        #proxy_set_header X-Forwarded-Proto $scheme;
        #proxy_buffering off;
	try_files $uri $uri/ =404;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl ipv6only=on;

    server_name <>; # Replace with your domain

    root /var/www/;
    index index.html index.htm;
    error_page 401 403 404 /404.html;
    client_max_body_size 10G;

    location / {
        #proxy_pass http://localhost:2368;
        #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #proxy_set_header Host $http_host;
        #proxy_set_header X-Forwarded-Proto $scheme;
        #proxy_buffering off;
    }

    ssl on;
    ssl_certificate /etc/nginx/conf.d/ssl-unified.crt;
    ssl_certificate_key /etc/nginx/conf.d/ssl.key;

    ssl_session_timeout 5m;
}


```

```
nginx -t
```

