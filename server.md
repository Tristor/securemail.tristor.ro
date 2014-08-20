#Building a Secure Email Server

This guide was heavily inspired by Drew Crawford's blog article [NSA-proof your e-mail in 2 hours](http://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/).  In the course of attempting to follow his guide I found several things that didn't work quite right and also wanted to harden the server in ways which would further enhance security.  Drawing from my experience as a 10+ year seasoned Linux/UNIX administrator and now Senior Systems Engineer, I felt some tweaks were in order.  This guide is my attempt at an updated and improved step-by-step how to.


Objectives
----------

* You're going to host your own mail.
* It's going to be encrypted on the server, locked-on-boot, with the requirement you must SSH in to unlock it if the server reboots.
* You're going to use a legitimate SSL certificate
* You will have your own secure webmail interface
* You will have best-in-class spam detection and handling
* You will meet all requirements to have your mail accepted as not spam by the strictest SMTP servers in the world (SPF, DKIM, TLS, PTR, etc.)
* Your web and email servers will operate on both IPv4 and IPv6
* Your server will be reasonably security hardened following best practices for all of the services we will install
* Your server will function quickly, with performance being a major consideration
* You will learn something useful

Note: Any server which is shared between users or purposes is inherently less secure than one which is dedicated to a specific purpose.  This is because of an increase in entry points and attack surface.  The techniques discussed within are general best practices, but there are additional steps that can be taken if needed.  For extremely high security environments you should engage the services of a security expert.

Attention: Some ISPs block outbound and/or inbound port 25 (SMTP). Trying to host this in your home may be doable, but also may not work or could be against your terms of service.  If at all possible host your email within a real datacenter.

Assumptions
-----------
Attention:  For this guide to be possible you **must** have your own domain and have control of DNS.

* You have your own domain and have control of DNS.
* You know basic Linux administration skills, more or less.
* You are running on Debian 7 (Wheezy).
* You have root access to the server
* You are capable of utilizing basic tools such as SSH, git, and a web browser
* You have nothing of importance on the server otherwise that might get messed up.
* You're capable of troubleshooting and using Google.

Hint: It's best to build this out on a cloud server or set of cloud servers if you don't have a dedicated server available.  This allows you to build the system without concern for impacting other users or use cases.  It also provides you something that is in a real data center to run this on.


Software We'll Be Installing
----------------------------

* [ufw - Uncomplicated Firewall](https://launchpad.net/ufw)
* [denyhosts](http://denyhosts.sourceforge.net/)
* [EncFS](http://www.arg0.net/encfs)
* [Postfix](http://www.postfix.org/)
* [Dovecot](http://www.dovecot.org/)
* [MySQL](https://www.mysql.com/)
* [OpenDKIM](http://www.opendkim.org/)
* [dspam](http://dspam.nuclearelephant.com/)
* [PigeonHole: Sieve for Dovecot](http://pigeonhole.dovecot.org/)
* [Postgrey](http://postgrey.schweikert.ch/)
* [postfwd](http://postfwd.org/)
* [BIND 9](https://www.isc.org/downloads/bind/)
* [Chrony](http://chrony.tuxfamily.org/)
* [nginx](http://nginx.org/)
* [PHP 5](http://php.net/)
* [PHP-FPM](http://php-fpm.org/)
* [mcrypt](http://postfwd.org/)
* [aspell](http://aspell.net/)
* [Roundcube](http://roundcube.net/)



Initial Server Configuration
----------------------------

###Before You Do Anything Else

Run the following:

```bash
apt-get update
apt-get upgrade -y
```

### Upgrade Your Kernel


Note: If you're an advanced user and want additional security, you should considering [installing a grsecurity](https://en.wikibooks.org/wiki/Grsecurity/Obtaining_grsecurity) enabled kernel.  This is a pretty laborious process, although on some platforms can be simplified by making use of [Debian Mempo](http://deb.mempo.org).  


We will install the latest kernel from backports.

```bash
apt-get -t wheezy-backports install linux-image-amd64
```

If you find you need to add backports to your sources, issue the following command before repeating the above:

```bash
echo "deb http://http.debian.net/debian wheezy-backports main" >> /etc/apt/sources.list.d/backports.list
apt-get update
```

### Change Your Root Password and Create a User

I advise using a password manager in general.  If you use one, use the random password generator function of it to make a root password that's at least 32 characters long, and store it in the password manager.  You won't need it shortly after we finish our initial configuration.

Replace $username with whatever you want your normal user account to be.  Note, it's being added to the sudoers group.

```bash
passwd
useradd -m -U -G sudo -s /bin/bash $username
```

### Basic SSH hardening

#####Generate SSH Keys

If you haven't already done so, you need to generate an SSH keypair to use for public-key authentication.  Below is a way to do this that has the advantage of making use of PKCS#8 private key encryption for further hardening.

The tool for generating keys is interactive, so you can follow the prompts.  It's highly recommended to use a descriptive name for your key, as we'll be adding it to the ssh-agent anyway.  So rather than ~/.ssh/id_rsa, I'd recommend ~/.ssh/id_myname.  In this version we'll be using a 4096-bit RSA key for best security.

When enabling PKCS#8, this ONLY for the private key.  Leave the public key unchanged.  ALWAYS set a strong passphrase for your SSH private keys.  Once again, this is a great use case for a password manager.

Run the following from your local client system:

```bash
ssh-keygen -t rsa -b 4096 
mv ~/.ssh/id_myname ~/.ssh/id_myname.old
umask 0077
openssl pkcs8 -topk8 -v2 3des -in ~/.ssh/id_myname.old -out ~/.ssh/id_myname
```

If your new key works in the next step, or still works on an existing system you used to login to, you can delete the old key.


##### Put Your Public Key on the Server


Attention: BEFORE making changes to disable password authentication ensure you've copied your SSH public key into the ~/.ssh/authorized_keys file in the home directory of your user on the server.  There is a tool call ssh-copy-id on many systems that will help you do this.  If you must do it manually, that is okay too, see immediately below for instructions.


Run the following from your client system:

```bash
scp ~/.ssh/id_myname.pub $username@example.com:~
```

Run the following from your server as your user:

```bash
mkdir .ssh
chmod 700 .ssh
cd .ssh
touch authorized_keys
chmod 600 authorized_keys
cat ~/id_myname.pub >> authorized_keys
rm ~/id_myname.pub
```

##### Configure the OpenSSH Server

Set the following options in /etc/ssh/sshd_config on the server:

```
UsePrivilegeSeparation yes
PermitRootLogin no
StrictModes yes
PubkeyAuthentication yes
PermitEmptyPasswords no
RSAAuthentication no
ChallengeResponseAuthentication no
PasswordAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding no
TCPKeepAlive yes
UsePAM yes

Ciphers aes256-ctr
MACs hmac-sha2-512
```

Save the file and then run the following to restart the OpenSSH service:

```bash
service ssh restart
```

Now, from ANOTHER terminal session on your local system, or another instance of your graphical SSH client (PuTTY et al) login to your server again to verify you can still get in under the new configuration with your SSH keypair.  If you can, and you should be able to, we're all good and able to move on to the next step.


Hint: If you're really security conscious you can use the AllowUsers parameter in the SSH server configuration to limit access over SSH to your server to just your specific username and IP.  Be aware this does limit flexibility some and using public-key authentication and denyhosts solves for most issues that could otherwise arise.

##### Install and Configure DenyHosts

DenyHosts is a tool which blocks people who are trying to bruteforce your SSH service by using TCPWrappers.  Other services like SSHGuard or Fail2Ban are usable as well, however I find that DenyHosts has some specific characteristics I prefer such as the ability to do central synchronization, which tends to be effective in preventing attackers from ever getting the chance to even see the first login prompt if they're doing large sweeps.  In addition, in my experience DenyHosts is less CPU intensive than Fail2Ban, and it makes it possible to only limit access to SSH without significant configuration hurdles.  Whitelisting is also more simplistic.


Attention: If you aren't careful you can lock yourself out of SSH access to your server.  Always configure a whitelist first by adding your IP to your hosts.allow file.  See Below.

Edit /etc/hosts.allow

```
ALL: $yourip
sshd: $yourip
```

Save it.


Install DenyHosts

```bash
apt-get install -y denyhosts
```

Configure DenyHosts


Most of the default settings are acceptable on Debian.  My changes are below.  The configuration file is well documented.

```
DENY_THRESHOLD_INVALID = 2
SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS=YES
SYNC_SERVER = http://xmlrpc.denyhosts.net:9911
SYNC_INTERVAL = 2h
SYNC_UPLOAD = yes
SYNC_DOWNLOAD = yes
SYNC_DOWNLOAD_THRESHOLD = 25
```

#####  Install ufw and Configure it for SSH

Note: If you are comfortable doing this with IPTables directly, go for it.

Install ufw

```bash
apt-get install -y ufw
```

Configure ufw for SSH

```bash
ufw default deny incoming
ufw allow ssh
ufw allow from $yourip
ufw enable
```

Hint: If you want to be even more secure, use default deny outgoing as well and enable only outgoing ports you need to specific IPs.  Such as ufw allow out to 8.8.8.8 port 53.  This does require much more effort though.  A future update of this guide may take this into account.

Hint: If you wish to be more secure, limit access to the SSH ports to only your IP by doing ufw allow from $yourip to any port 22.  Just be aware that this limits your flexibility and may be problematic if you only have your home IP in there, since your home connection probably has a dynamic IP.



### Enable Automatic Security Updates

We'll enable automatic security updates using unattended-upgrades and some APT settings.


```bash
apt-get install -y unattended-upgrades
```

Ensure /etc/apt/apt.conf.d/10periodic has the following (you may need to create this):

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

Ensure that /etc/apt/apt.conf.d/50unattended-upgrades has the following:

```
// Automatically upgrade packages from these origin patterns
Unattended-Upgrade::Origins-Pattern {
        // Archive or Suite based matching:
        // Note that this will silently match a different release after
        // migration to the specified archive (e.g. testing becomes the
        // new stable).
//      "o=Debian,a=stable";
//      "o=Debian,a=stable-updates";
//      "o=Debian,a=proposed-updates";
        "origin=Debian,archive=stable,label=Debian-Security";
};
```


Initial DNS Configuration
-------------------------

Attention: Before we continue any further, please ensure that you have an A, AAAA, MX, and SPF record created.  Additionally if possible, you need to set your PTR to match your A record. This will make the rest of this easier.

As an example, here is the DNS configuration for the email server on this domain, mail.tristor.ro.

```
mail.tristor.ro.	300	IN	A	23.253.125.249
mail.tristor.ro.	300	IN	AAAA	2001:4800:7817:103:be76:4eff:fe04:f5fe
tristor.ro.		300	IN	MX	10 mail.tristor.ro.
tristor.ro.		300	IN	TXT	"v=spf1 mx ip4:23.253.125.249/32 -all"
mail._domainkey.tristor.ro.	300	IN	TXT	"v=DKIM1; h=sha256; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrhdZgI0Qnig0wTNERIdeqY4j1I8t5F6upIoB/s7cNfab5bpui0hCxppAy926rOZ5TmMO1gXP5zCKy6JPWUUFF9hANFonXkawZjRq5oMYOnQ0EOhUqw86ezv2sX6sJbI1gaN7kpa3/FNn3utJkAH4iu7RT0JK4ff0ym7xXQ8HRYQIDAQAB"
```

We'll get to the DKIM configuration later, which is when you will generate your proper ._domainkey entry.  Until then, don't worry about that one, but I've included it here for posterity.


Configure EncFS
---------------

Now we get to configuring our encrypted mail store.  This will be used for storing all of the mail data, as well as cache data for the various services in our service chain.  Each time your system is rebooted you'll need to login to your server and run the encfs command to decrypted and remount the mail store.  Afterwards you'll need to restart postfix, dovecot, opendkim, postfwd, and postgrey since they expect to be able to read and write data from the mail store.

Note: Each time you do this you'll need to enter your password, so whatever you choose ensure you don't forget it.  This too can be stored in your password manager.

A simple shell script for your root user that can do this is as follows:

```bash
#!/bin/sh
#mount_mail.sh
encfs /mail/encrypted-mail /mail/decrypted-mail --public
chgrp mail /mail/decrypted-mail/
chmod -R g+rw /mail/decrypted-mail/
sleep 5

#restart services
service postfwd restart
service postgrey restart
service opendkim restart
service postfix restart
service dovecot restart
```

Alright, here goes:

```bash
apt-get install -y encfs
mkdir -pv /mail/{encrypted-mail,decrypted-mail}
gpasswd -a mail fuse
chgrp fuse /dev/fuse; chmod g+rw /dev/fuse
encfs /mail/encrypted-mail /mail/decrypted-mail --public
```

You should choose to enable paranoia mode and then enter a good password twice.  You should see output like the following:

```
Creating new encrypted volume.
Please choose from one of the following options:
 enter "x" for expert configuration mode,
 enter "p" for pre-configured paranoia mode,
 anything else, or an empty line will select standard mode.
?> p
Paranoia configuration selected.
Configuration finished.  The filesystem to be created has
the following properties:
Filesystem cipher: "ssl/aes", version 3:0:2
Filename encoding: "nameio/block", version 3:0:1
Key Size: 256 bits
Block Size: 1024 bytes, including 8 byte MAC header
Each file contains 8 byte header with unique IV data.
Filenames encoded using IV chaining mode.
File data IV is chained to filename IV.
File holes passed through to ciphertext.
-------------------------- WARNING --------------------------
The external initialization-vector chaining option has been
enabled.  This option disables the use of hard links on the
filesystem. Without hard links, some programs may not work.
The programs 'mutt' and 'procmail' are known to fail.  For
more information, please see the encfs mailing list.
If you would like to choose another configuration setting,
please press CTRL-C now to abort and start over.
Now you will need to enter a password for your filesystem.
You will need to remember this password, as there is absolutely
no recovery mechanism.  However, the password can be changed
later using encfsctl.
New Encfs Password:
Verify Encfs Password:
```

In the case of my configuration, I was using a [Performance Cloud Server from Rackspace](http://www.rackspace.com/cloud/).  These have a 40GB primary volume for / and a 20, 40, or 80GB secondary volume that is unpartitioned.  I partitioned my secondary volume as one partition, formatted it as EXT4, and mounted it to /mail and set it in my /etc/fstab.  If your configuration does not allow you to put the mail on its own partition, a folder is fine too.  EncFS does not care either way.


Postfix
-------

Let's install Postfix, Dovecot, and MySQL to start.  You're going to get prompted for some things by dpkg-configure when you install Postfix.  You want to choose "Internet Site" and then set your "mail name" to match the domain that should follow the @ sign in emails and matches your MX record.  So in my case, I chose "tristor.ro".


```bash
apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-mysql mysql-server dovecot-lmtpd
```

The first thing we need to do is configure our MySQL server to have the appropriate database and tables for virtual domains, users, and aliases for Postfix and Dovecot.  Before we do that though, if you did not set a password for the MySQL root user during install, you will do so shortly as we'll be doing some hardening for MySQL.

### MySQL Hardening

##### mysql_secure_installation

The first step is to run mysql_secure_installation which will fix a number of basic things.  When executed the script will first request your root password if you already have one set, and then it will give you an opportunity to change it or set it.  Then you will get a series of questions which you should choose "yes" to.  These will do the following actions:

* Ensure 'root' has a password set
* Remove remote access to the 'root' account
* Remove anonymous user accounts
* Remove the test database
* Reloads the privilege tables to make changes take effect immediately

```bash
mysql_secure_installation
```


##### Additional manual steps

The default Debian MySQL configuration is relatively secure.  There are a few things that can be done to further harden it. Edit your /etc/mysql/my.cnf by doing the following.

```
[mysqld]
set-variable=local-infile=0
skip-show-database
```
This will remove the ability for the "show databases;" command to be used at the MySQL prompt and will remove the ability to use LOCAL INFILE commands, which prevents an SQLI attack from reading your /etc/passwd et al

Hint: Later in this tutorial when we do some final hardening we'll also remove your MySQL history file, since it contains schema information and passwords from commands which we'll be executing.  

### MySQL DB/Table Creation

When prompted for your MySQL 'root' password you will need to enter it.  We will be creating a database and series of tables and a user that your other services will connect to MySQL with.

Attention:   Please use a UNIQUE password for 'mailuser', not the same as used for 'root'.  This will be substituted in your query for $mailuserpass as below.

Create DB and User.
```
mysqladmin -p create mailserver
mysql -p mailserver
mysql> GRANT SELECT ON mailserver.* TO 'mailuser'@'127.0.0.1' IDENTIFIED BY '$mailuserpass';
FLUSH PRIVILEGES;
```

Note: You'll need to remember what the "mail name" that was set for Postfix configuration during installation was.  This will be your base virtual domain, which will replace the variable $mailname in the query below.

Now we can create all the tables and the primary virtual domain

```sql
CREATE TABLE virtual_domains (
  id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE virtual_users (
  id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id INT(11) NOT NULL,
  password VARCHAR(106) NOT NULL,
  email VARCHAR(100) NOT NULL,
  UNIQUE KEY email (email),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE virtual_aliases (
  id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id INT(11) NOT NULL,
  source VARCHAR(100) NOT NULL,
  destination VARCHAR(100) NOT NULL,
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
INSERT INTO mailserver.virtual_domains (id, name) VALUES (1, "$mailname");
```

Now we need to make your email address.  Use Dovecot's admin tool to create the password hash.

```
doveadm pw -s SHA512-CRYPT
Enter new password: 
Retype new password: 
```

The hash it returns is split into two parts, one is the hash type declaration, and the other is the hash string.  You need to insert the hash string into the database where the variable $passwordhash is located in the following INSERT query.  The hash string for SHA512-CRYPT will always start with "$6$"

```
{SHA512-CRYPT}$6$xlPWvhVDQ0p.LUAL$FVsyDqUQVeRh/YNx5DEvoHQ90c7BX4PfcY8V3lYaxqJ0BjRyx/EQ8z/QE2eScaEQ7jG7fFz9dshOpKV0y/qbZ.
```

Create your first email account and alias
```sql
INSERT INTO mailserver.virtual_users (id, domain_id, password, email) VALUES (1, 1, "$passwordhash", "$youremailaddress");
INSERT INTO mailserver.virtual_aliases (id, domain_id, source, destination) VALUES (1, 1, "postmaster@$mailname", "$youremailaddress");

```

We'll finally ready to begin working on configuring Postfix.

### Postfix Main Configuration File

First let's backup your existing Postfix configuration

```bash
cp /etc/postfix/main.cf /etc/postfix/main.cf.orig
cp /etc/postfix/master.cf /etc/postfix/master.cf.orig
```

Note: you will need to provide a self-signed certificate if you don't want to purchase a legitimate trusted certificate.  I purchased my RapidSSL through [Namecheap](http://www.namecheap.com/?aff=72423) for $38 for 4 years which was one of the best prices I found.  

Attention: If you choose to purchase a certificate, you will need to START with a self-signed, because a verification email to postmaster@yourdomain.com is sent as part of the domain validation process.  

Edit your /etc/postfix/main.cf configuration to look like the following. 
```
# See /usr/share/postfix/main.cf.dist for a commented, more complete version


# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# The server only allows modes that provide perfect forward secrecy, they are
# required. Anonymous cipher modes are disabled.
#
#  Supported Server Cipher(s):
#    Accepted  TLSv1  256 bits  DHE-RSA-AES256-SHA
#    Accepted  TLSv1  128 bits  DHE-RSA-AES128-SHA
#
#  Preferred Server Cipher(s):
#    TLSv1  256 bits  DHE-RSA-AES256-SHA

# TLS parameters
#smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
#smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
#smtpd_use_tls=yes
#smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
#smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
#Configuring to work with Dovecot using TLS
smtpd_tls_cert_file=/etc/ssl/certs/tristor.ro.combined.crt
smtpd_tls_key_file=/etc/ssl/private/tristor.ro.key
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, DES-CBC3-SHA, RC4-SHA, AES256-SHA, AES128-SHA
smtpd_use_tls=yes
smtp_tls_protocols = !SSLv2, SSLv3, TLSv1
smtpd_tls_mandatory_protocols = TLSv1, TLSv1.1, TLSv1.2
smtpd_tls_mandatory_ciphers = high
tls_high_cipherlist = ECDH+aRSA+AES256:ECDH+aRSA+AES128:AES256-SHA:DES-CBC3-SHA
smtp_tls_note_starttls_offer = yes
smtpd_tls_received_header = yes
smtpd_tls_session_cache_database = btree:${queue_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${queue_directory}/smtp_scache
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtp_tls_loglevel = 2

#Use SASL for Dovecot

smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_recipient_restrictions =
        permit_sasl_authenticated,
        permit_mynetworks,
        reject_unauth_pipelining,
        reject_non_fqdn_recipient,
        reject_unknown_recipient_domain,
        reject_unauth_destination
        
smtpd_helo_required = yes

# waste spammers time before rejecting them
smtpd_delay_reject = yes
disable_vrfy_command = yes

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

myhostname = mail.tristor.ro
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
#destination is localhost only since it's relaying to Dovecot
mydestination = localhost
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all

#Additional virtual host config
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf
local_recipient_maps = $virtual_mailbox_maps

#DKIM Config
smtpd_milters           = inet:127.0.0.1:8891
non_smtpd_milters       = $smtpd_milters
milter_default_action   = accept

# new settings for dspam
dspam_destination_recipient_limit = 1 
#only scan one mail at a time
smtpd_client_restrictions =
   permit_sasl_authenticated
   check_client_access pcre:/etc/postfix/dspam_filter_access
   check_policy_service inet:127.0.0.1:10040
```

The changes made from the defaults in the above configuration file essentially do the following:

* Configure TLS with secure settings ensuring Perfect Forward Secrecy
* Configure SASL for use when connecting between Postfix and Dovecot on your server
* Set Postfix to only relay mail locally, since Dovecot will handle IMAP
* Configure it to transport over LMTP
* Configure it to use MySQL maps for virtual domains, aliases, and users.
* Configure mail to go through OpenDKIM (which we will configurate later)
* Configure mail to go through dspam and postfwd(which we will configure later)

Now we're going to create those MySQL maps, as before $mailuserpass needs to be filled in with the password of the 'mailuser' DB user you created previously.

/etc/postfix/mysql-virtual-mailbox-domains.cf
```
user = mailuser
password = $mailuserpass
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
```

/etc/postfix/mysql-virtual-mailbox-maps.cf
```
user = mailuser
password = $mailuserpass
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
```

/etc/postfix/mysql-virtual-alias-maps.cf
```
user = mailuser
password = $mailuserpass
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
```


At this point you should restart Postfix and verify that your virtual mapping works.

```bash
service postfix restart
postmap -q $mailname mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
postmap -q $youremailaddress mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
``` 

postmap will respond with '1' if everything worked properly.


Now we will change your second Postfix config file before we move on.

### Postfix Master Config File

Now we edit /etc/postfix/master.cf. You've already backed this file up, so just make it look like below essentially.


```
#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master").
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       -       -       -       smtpd
#smtp      inet  n       -       -       -       1       postscreen
#smtpd     pass  -       -       -       -       -       smtpd
#dnsblog   unix  -       -       -       -       0       dnsblog
#tlsproxy  unix  -       -       -       -       0       tlsproxy
submission inet n       -       -       -       -       smtpd
#  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       -       -       -       smtpd
#  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       -       -       -       qmqpd
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
#qmgr     fifo  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about ${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#
# ====================================================================
#
# Recent Cyrus versions can use the existing "lmtp" master.cf entry.
#
# Specify in cyrus.conf:
#   lmtp    cmd="lmtpd -a" listen="localhost:lmtp" proto=tcp4
#
# Specify in main.cf one or more of the following:
#  mailbox_transport = lmtp:inet:localhost
#  virtual_transport = lmtp:inet:localhost
#
# ====================================================================
#
# Cyrus 2.1.5 (Amos Gouaux)
# Also specify in main.cf: cyrus_destination_recipient_limit=1
#
#cyrus     unix  -       n       n       -       -       pipe
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#
# ====================================================================
# Old example of delivery via Cyrus.
#
#old-cyrus unix  -       n       n       -       -       pipe
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
#
# Other external delivery methods.
#
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix  -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}

#Added to support dspam and dovecot-sieve
dspam     unix  -       n       n       -       10      pipe
  flags=Ru user=dspam argv=/usr/bin/dspam --deliver=innocent,spam --user $recipient -i -f $sender -- $recipient
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=mail:mail argv=/usr/lib/dovecot/deliver -f ${sender} -d ${recipient}
```

This will enable Submission (StartTLS compliant SMTPd) with appropriate options, SMTPS (SSL complient SMTPd) with appropriate options, and add hooks for dspam and dovecot-sieve (which will be setup later)

This config file is now finished, or should be.


Dovecot
-------

First let's backup your existing configuration files

```bash
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig
cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.orig
cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.orig
cp /etc/dovecot/dovecot-sql.conf.ext /etc/dovecot/dovecot-sql.conf.ext.orig
cp /etc/dovecot/conf.d/10-master.conf /etc/dovecot/conf.d/10-master.conf.orig
cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.orig
cp /etc/dovecot/conf.d/10-logging.conf /etc/dovecot/conf.d/10-logging.conf.orig
```

First let's edit the main Dovecot configuration file, /etc/dovecot/dovecot.conf

Down at the bottom enable imap and lmtp
```
protocols = imap lmtp
```

Then change /etc/dovecot/conf.d/10-mail.conf so the variables below match my provided parameters

```
mail_location = maildir:/mail/decrypted-mail/%d/%n
mail_privileged_group = mail
first_valid_uid = 0
```

Now we edit the auth configuration in /etc/dovecot/conf.d/10-auth.conf

Note: In this file we'll be commenting out with a '#' one line, and uncommenting another to use MySQL rather than local UNIX accounts for auth down near the bottom in addition to changing the other two parameters.

```
disable_plaintext_auth = yes
auth_mechanisms = plain login
#!include auth-system.conf.ext
!include auth-sql.conf.ext
```

Now let's configure Dovecot's SQL extension in /etc/dovecot/conf.d/auth-sql.conf.ext

```
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=mail gid=mail home=/decrypted-mail/%d/%n
}
```

And finally now we configure Dovecot to connect to the proper database in /etc/dovecot/dovecot-sql.conf.ext  

Note: You will need to provide the password for your 'mailuser' DB user where $mailuserpass is.

```
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$mailuserpass
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';
```

Now we need to set some permissions on the Dovecot configuration so the mail group can work within it.

```bash
chown -R mail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot
```

Finally we're going to do a config hack in Dovecot that forces the use of secure sockets by setting the listener ports to 0 and configure our LMTP service by editing /etc/dovecot/conf.d/10-master.conf

```
service imap-login {
  inet_listener imap {
    port = 0
  }
  
service pop3-login {
  inet_listener pop3 {
    port = 0
  }


service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0666
    group = postfix
    user = postfix
  }
  # Create inet listener only if you can't use the above UNIX socket
  #inet_listener lmtp {
    # Avoid making LMTP visible for the entire internet
    #address =
    #port =
  #}
  user=mail
}
```

One last edit to that same file is to replace the entire service auth and service auth-worker sections with what I provide below:

```
service auth {
  # auth_socket_path points to this userdb socket by default. It's typically
  # used by dovecot-lda, doveadm, possibly imap process, etc. Its default
  # permissions make it readable only by root, but you may need to relax these
  # permissions. Users that have access to this socket are able to get a list
  # of all usernames and get results of everyone's userdb lookups.
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
  unix_listener auth-userdb {
    mode = 0600
    user = mail
    #group =
  }
  # Postfix smtp-auth
  #unix_listener /var/spool/postfix/private/auth {
  #  mode = 0666
  #}
  # Auth process is run as this user.
  user = dovecot
}
service auth-worker {
  # Auth worker process is run as root by default, so that it can access
  # /etc/shadow. If this isn't necessary, the user should be changed to
  # $default_internal_user.
  user = mail
}
```

Next we're going to configure Dovecot logging to show what cipher suite is being used when it logs by editing /etc/dovecot/conf.d/10-logging.conf

```
login_log_format_elements  =  "user = <% u> method =% m% r rip = lip =% l MPID =% s% c% k"
```

And finally we will do our SSL configuration in /etc/dovecot/conf.d/10-ssl.conf.  See below for my complete configuration which enforces TLSv1+ and Perfect Forward Secrecy

```
##
## SSL settings
##

# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = required

# PEM encoded X.509 SSL/TLS certificate and private key. They're opened before
# dropping root privileges, so keep the key file unreadable by anyone but
# root. Included doc/mkcert.sh can be used to easily generate self-signed
# certificate, just make sure to update the domains in dovecot-openssl.cnf
ssl_cert = </etc/ssl/certs/tristor.ro.combined.crt
ssl_key = </etc/ssl/private/tristor.ro.key

# If key file is password protected, give the password here. Alternatively
# give it when starting dovecot with -p parameter. Since this file is often
# world-readable, you may want to place this setting instead to a different
# root owned 0600 file by using ssl_key_password = <path.
#ssl_key_password =

# PEM encoded trusted certificate authority. Set this only if you intend to use
# ssl_verify_client_cert=yes. The file should contain the CA certificate(s)
# followed by the matching CRL(s). (e.g. ssl_ca = </etc/ssl/certs/ca.pem)
#ssl_ca = 

# Require that CRL check succeeds for client certificates.
#ssl_require_crl = yes

# Request client to send a certificate. If you also want to require it, set
# auth_ssl_require_client_cert=yes in auth section.
#ssl_verify_client_cert = no

# Which field from certificate to use for username. commonName and
# x500UniqueIdentifier are the usual choices. You'll also need to set
# auth_ssl_username_from_cert=yes.
#ssl_cert_username_field = commonName

# How often to regenerate the SSL parameters file. Generation is quite CPU
# intensive operation. The value is in hours, 0 disables regeneration
# entirely.
#ssl_parameters_regenerate = 168

# SSL protocols to use
ssl_protocols = !SSLv2 !SSLv3 TLSv1 
#Debian 7 and Debian 8 both use Dovecot 2.1.7 + patches
#New TLS modes are only supported in Dovecot 2.2.
#If you're using Dovecot 2.2, please ensure to enable the below as well.'
#TLSv1.1 TLSv1.2

# SSL ciphers to use
#ssl_cipher_list = ALL:!LOW:!SSLv2:!EXP:!aNULL
ssl_cipher_list = ECDH+aRSA+AES256:ECDH+aRSA+AES128:AES256-SHA:DES-CBC3-SHA

# SSL crypto device to use, for valid values run "openssl engine"
#ssl_crypto_device =
```


Attention: At this point email should basically work, however since we did some pre-configuration it won't.  We still need to configure PigeonHole, postfwd, postgrey, OpenDKIM, and dspam.  

Before we move on to that, though, here's a quick primer on how to generate a self-signed certificate and key for use with Postfix and Dovecot until you can get a real cert.

```bash
openssl req -new -x509 -days 1000 -nodes -out "/etc/ssl/certs/dovecot.pem" -keyout "/etc/ssl/private/dovecot.pem"
```
Hint: Anywhere you've seen me specify my certificates you can instead specify these so that you can get TLS working long enough to receive the DV validation email.  

Attention: Again, I highly recommend you use a trusted cert, even if it's just for your personal use, because it will condition you to be alert around seeing certificate warnings, rather than accepting them.  Less than $40 for 4 years at [Namecheap](http://www.namecheap.com/?aff=72423) is pretty cheap.


Anti-Spam Configuration
-----------------------

### OpenDKIM

This is going to be relatively quick and painless, however you'll need to make some DNS entries as I alluded to near the beginning of this document.  

Note: Fill in $mailname with the 'mail name' you used in Postfix and previously.

```bash
apt-get install -y opendkim opendkim-tools
mkdir -pv /etc/opendkim/
chown -Rv opendkim:opendkim /etc/opendkim
chmod go-rwx -R /etc/opendkim
cd /etc/opendkim/
opendkim-genkey -r -h rsa-sha256 -d $mailname -s mail
mv -v mail.private mail
cat mail.txt
```

The final step will output the DKIM key to the terminal, however by default it puts the hash value as rsa-sha256, which should actually be just sha256.  See below for a valid example from my configuration

```
mail._domainkey.tristor.ro.	300	IN	TXT	"v=DKIM1; h=sha256; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrhdZgI0Qnig0wTNERIdeqY4j1I8t5F6upIoB/s7cNfab5bpui0hCxppAy926rOZ5TmMO1gXP5zCKy6JPWUUFF9hANFonXkawZjRq5oMYOnQ0EOhUqw86ezv2sX6sJbI1gaN7kpa3/FNn3utJkAH4iu7RT0JK4ff0ym7xXQ8HRYQIDAQAB"
```

At any rate make your DNS changes and then you need to create your KeyTable, SigningTable, and TrustHosts files.  Modifying the below to match your appropriate 'mail name'

/etc/opendkim/KeyTable
```
tristor.ro tristor.ro:mail:/etc/opendkim/mail
```

/etc/opendkim/SigningTable
```
*@tristor.ro tristor.ro
```

/etc/opendkim/TrustedHosts
```
127.0.0.1
```

Finally you have to make your OpenDKIM configuration file.

/etc/opendkim.conf
```
##
## opendkim.conf -- configuration file for OpenDKIM filter
##
Canonicalization        relaxed/relaxed
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
LogWhy                  Yes
MinimumKeyBits          1024
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SigningTable            refile:/etc/opendkim/SigningTable
Socket                  inet:8891@localhost
Syslog                  Yes
SyslogSuccess           Yes
TemporaryDirectory      /var/tmp
UMask                   022
UserID                  opendkim:opendkim
```

Note: Since making these files may have caused them to be owned by root instead of the opendkim user, we need to change their ownership again to be sure (this resolves an issue with 4.7.1 errors I saw) although we want to ensure the opendkim user doesn't have write permissions to the private key.

```bash
chown -Rv opendkim:opendkim /etc/opendkim
chown root:opendkim /etc/opendkim/mail
chmod g+r /etc/opendkim/mail
```

Postfix was pre-configured to work with OpenDKIM so we just need to bounce the services and move on.

```bash
service opendkim restart
service postfix restart
```

Your SPF configuration should have already been completed previously, but just as an example here is my working config again.  If you haven't made this change yet, you need your SPF configuration done as well in DNS, might as well do it at the same time you're doing the OpenDKIM stuff.

```
tristor.ro.		300	IN	TXT	"v=spf1 mx ip4:23.253.125.249/32 -all"
```

Attention: You should also be setting your Reverse DNS information for both IPv4 and IPv6 on your server.  This is known as the PTR or pointer record.  As an example, this is done from the server details page in the Cloud Control Panel if you're using a [Rackspace Cloud Server](http://www.rackspace.com/cloud/).  Otherwise you should check the documentation from your hosting service or contact their Support services for assistance.


### dspam and PigeonHole

Note: You can use any anti-spam service you like, however for my preferences and the purpose of this tutorial we will be using dspam.  Another popular tool is SpamAssasin, however if you use SpamAssasin you will need to make some significant changes to the anti-spam configuration since SpamAssasin replaces the need for postfwd and integrates directly with PigeonHole and Postgrey.  This could be beneficial to you, but I find my configuration more simplistic and equal or better in effectiveness.

```bash
apt-get install -y dspam dovecot-antispam postfix-pcre dovecot-sieve
```

Make changes to your /etc/dspam/dspam.conf so that the follow paramaters match my provided configuration (some are changes, some are additions)

```
Home /mail/decrypted-mail/dspam
TrustedDeliveryAgent "/usr/sbin/sendmail"
UntrustedDeliveryAgent "/usr/lib/dovecot/deliver -d %u"
Tokenizer osb
IgnoreHeader X-Spam-Status
IgnoreHeader X-Spam-Scanned
IgnoreHeader X-Virus-Scanner-Result
IgnoreHeader X-Virus-Scanned
IgnoreHeader X-DKIM
IgnoreHeader DKIM-Signature
IgnoreHeader DomainKey-Signature
IgnoreHeader X-Google-Dkim-Signature
ParseToHeaders on
ChangeModeOnParse off
ChangeUserOnParse full
ServerPID  /var/run/dspam/dspam.pid
ServerDomainSocketPath "/var/run/dspam/dspam.sock"
ClientHost /var/run/dspam/dspam.sock
```

Then create the dspam home directory.

```bash
mkdir -pv /mail/decrypted-mail/dspam
chown dspam:dspam /mail/decrypted-mail/dspam
```

Edit the delivery rules in /etc/dspam/default.prefs

```
spamAction=deliver         # { quarantine | tag | deliver } -> default:quarantine
signatureLocation=headers  # { message | headers } -> default:message
showFactors=on
```

Now edit the postfix dspam rule file in /etc/postfix/dspam_filter_access
```
/./   FILTER dspam:unix:/run/dspam/dspam.sock
```

Now we edit Dovecot configuration to integrate dspam and PigeonHole into IMAP and LMTP

Edit /etc/dovecot/conf.d/20-imap.conf

```
mail_plugins = $mail_plugins antispam
```

Edit /etc/dovecot/conf.d/20-lmtp.conf

```
mail_plugins = $mail_plugins sieve
```

Now we need to create a configuration to tell PigeonHole to move spam into a Spam IMAP folder for your user.  Edit /mail/decrypted-mail/$mailname/$virtualuser/.dovecot.sieve

```
require ["regex", "fileinto", "imap4flags"];
# Catch mail tagged as Spam, except Spam retrained and delivered to the mailbox
if allof (header :regex "X-DSPAM-Result" "^(Spam|Virus|Bl[ao]cklisted)$",
          not header :contains "X-DSPAM-Reclassified" "Innocent") {
  # Mark as read
  setflag "\\Seen";
  # Move into the Junk folder
  fileinto "Spam";
  # Stop processing here
  stop;
}
```

Then we edit /etc/dovecot/conf.d/90-plugin.conf.  We'll be adding some lines into the plugin{} dictionary.

```
   # Antispam (DSPAM)
   antispam_backend = dspam
   antispam_allow_append_to_spam = YES
   antispam_spam = Spam;Junk
   antispam_trash = trash;Trash
   antispam_signature = X-DSPAM-Signature
   antispam_signature_missing = error
   antispam_dspam_binary = /usr/bin/dspam
   antispam_dspam_args = --user;%u;--deliver=;--source=error
   antispam_dspam_spam = --class=spam
   antispam_dspam_notspam = --class=innocent
   antispam_dspam_result_header = X-DSPAM-Result
```

Now bounce postfix and dovecot

```bash
service postfix restart
service dovecot restart
```

### Postfwd, Postgrey, DNSBLs, and BIND

Alright, so the final anti-spam measure we'll be taking is using hybrid greylisting based off DNSBL scoring.  To accomplish this in a performant manner we'll be configuring BIND9 to act as a local DNS cache as well.

```bash
apt-get install postgrey postfwd bind9 dnsutils chrony 
```

First let's configure chrony and BIND

##### DNS Caching Configuration

Attention: chrony's default configuration is correct and it is useful in keeping time correct which is important for many things, among those is DNS caching.  There is no need to adjust it's configuration, but you should be aware that VMs (such as cloud servers) tend to be very bad at keeping accurate time and drift heavily under load.  So chrony is non-optional for a working configuration.

The default BIND configuration has it acting as a caching nameserver already.  So the only action required is configuring it's upstream nameservers.

Check your /etc/resolv.conf file to find out your current nameservers.  In my case, mine are 72.3.128.240 and 72.3.128.241

Now edit /etc/bind/named.conf.options and fill in the forwarders block.

```
	forwarders {
	 	72.3.128.240;
		72.3.128.241;
	};
```

Now we're going to correctly regenerate your /etc/resolve.conf file.  Firstly, edit /etc/network/interfaces and comment out any lines starting with dns-nameservers under the interface configuration.  Then add the following to /etc/resolvconf/resolv.conf.d/base

```
#Use local BIND9 install as caching resolver.
nameserver 127.0.0.1
#Original Nameservers
#72.3.128.140
#72.3.128.141
```

Now we will use resolvconf to regenerate our /etc/resolv.conf file and verify it works so the file will contain correct information on reboots.

```bash
resolveconf -a eth0.inet
resolveconf -u
```

Now cat /etc/resolv.conf and it should say

```
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
nameserver 127.0.0.1
```

Now restart BIND

```bash
service bind9 restart
```

Let's verify that the caching function is working.  Pick a domain to use that you haven't hit before from that server.  I'm going to use cnn.com as an example.  Run the following twice and compare the times.

```
time dig cnn.com
```

You should see the first query take some amount of time, followed by the second query taking almost no time (less than 5ms).  This is the performance potential of DNS caching in a nutshell.  

Hint: By caching the results of DNSBLS, it'll be able to process mail much faster.  This works because a DNSBL operates by your server essentially doing a dig at a special URL with the IP and the DNSBL returns a DNS response via normal means.  So your nameserver is able to cache the response for each DNSBL effectively.

##### Postfwd and Postgrey configuration

Now we need to enable daemon mode for postfwd

Edit /etc/default/postfwd and change STARTUP=0 to STARTUP=1

Now let's create our postfwd config.

Edit /etc/postfix/postfwd.cf

```
#DNS Blocklist Declaration

&&DNSBLS {
	rbl=zen.spamhaus.org ; \
	rbl=bl.spamcop.net ; \
	rbl=safe.dnsbl.sorbs.net ; \
	rbl=black.uribl.com ; \
	rhsbl=rhsbl.sorbs.net ; \	
};

# Needs rbl=b.barracudacentral.org added back once registration succeeds
#DNSBL Checks - Lookup
id=RBL_QUERY ; &&DNSBLS ; rhsblcount=all ; rblcount=all ; \
  action=set(HIT_dnsbls=$$rhsblcount,HIT_dnsbls+=$$rblcount,DSBL_text=$$dnsbltext)

#DNSBL Checks - Eval
id=RBL_TOOMANY ; HIT_dnsbls>=3 ; \
  action=554 5.7.1 blocked using $$DSBL_count dnsbls, INFOL [$$DSBL_text]

#Greylist
id=GREYLIST ; action=ask(127.0.0.1:10023) ; HIT_dnsbls>=1
```

This configuration will check the DNSBLs we've included and if an address is listed on 3 or more, that mail is rejected.  If it's on less than 3 but on at least 1, it'll get greylisted.  If it's on none, it passes through and avoids greylisting greatly increasing mail performance while still getting the advantages of greylisting for spam protection.

Now bounce your services
```bash 
service postfwd restart
service postgrey restart
service postfix restart
```

At this point you should be able to send and recieve mail via an IMAP/SMTP client such as Thunderbird.  We will be configuring the webmail service next, which will give you secure web-based email on your server.  

Note: I will cover the email client configuration in another tutorial accessible from the menu at the top.


WebMail Configuration
---------------------

The last service we need to setup is going to be nginx, php-fpm, and a web application called 'roundcube'.  We will be installing nginx from wheezy-backports, because it is a much newer version which enables some additional security functionality called OCSP stapling.

```bash
apt-get -t wheezy-backports install -y nginx
apt-get install -y php5-fpm php5-mysql php-pear php5-mcrypt php5-dev aspell libicu44 libicu-dev
pecl install intl
```

We're going to put our configuration for nginx into a file named /etc/nginx/sites-available/roundcube

Note: You'll need to ensure that you change the server_name parameter to match your appropriate URL and also set your SSL certificate and key to your self-signed or the appropriate one provided by your CA.

```
#rate limit requests to prevent bruteforce
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;

server {
    listen      80;
#    listen     [::]:80;
    server_name mail.tristor.ro;
    return 301  https://$server_name$request_uri;
}


server {
        listen   443 default_server ssl;
#       listen  [::]:443;
     
        root /usr/share/nginx/www/roundcube;
        index index.php index.html index.htm;

        server_name mail.tristor.ro;

        ssl_certificate /etc/ssl/certs/tristor.ro.combined.crt;
        ssl_certificate_key /etc/ssl/private/tristor.ro.key;

        #Enable Perfect Forward Secrecy
        ssl_dhparam /etc/ssl/dhparam.pem;

        #These should go in /etc/nginx/nginx.conf
        #ssl_session_timeout 10m;
        #ssl_session_cache shared:SSL:50m;

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        #ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS +RC4 RC4";
        ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

        #Enable this for HSTS (recommended, but be careful)
        add_header Strict-Transport-Security "max-age=15768000; includeSubdomains";

        #OCSP Stapling
        #fetch OCSP records from URL in ssl_certificate and cache them
        ssl_stapling on;
        ssl_stapling_verify on;
        #verify chain of trust of OCSP response using Root CA and Intermediate certs
        ssl_trusted_certificate /etc/ssl/certs/rapidssl.ca-inter.crt;
        resolver 127.0.0.1;

        location / {
                try_files $uri $uri/ /index.html;
                limit_req       zone=one burst=10 nodelay;
        }

        error_page 404 /404.html;

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
              root /usr/share/nginx/www;
        }

        # pass the PHP scripts to FastCGI server listening on /var/run/php5-fpm.sock
        location ~ \.php$ {
                try_files $uri =404;
                fastcgi_pass unix:/var/run/php5-fpm.sock;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                include fastcgi_params;
                
        }

}
```

Add the following inside the http{} block in /etc/nginx/nginx.conf
```
        #SSL session caching, ssl performance
        ssl_session_cache shared:SSL:50m;
        ssl_session_timeout 10m;
```

Now let's get roundcube downloaded and it's files put into the right place

```bash
cd ~
wget http://sourceforge.net/projects/roundcubemail/files/roundcubemail/1.0.2/roundcubemail-1.0.2.tar.gz/download
mv download roundcubemail-1.0.2.tar.gz
tar xvf roundcubemail-1.0.2.tar.gz
mkdir -pv /usr/share/nginx/www/roundcube
cp ~/roundcubemail-1.0.2/* /usr/share/nginx/www/roundcube/
```

Now that this is out of the way, we need to configure PHP.

In /etc/php5/fpm/php.ini there are two sets of changes that need to be made.  The first is changing a parameter, the second is adding something at the bottom of the file.

Change:
```
cgi.fix_pathinfo=0
```

Add to bottom:
```
;For PECL install of INTL
extension=intl.so
```

Then in /etc/php5/fpm/pool.d/www.conf uncomment the following two lines
```
listen.owner = www-data
listen.group = www-data
```

Create your DHParam for nginx:

```bash
openssl dhparam -rand - 2048 >> /etc/ssl/dhparam.pem
```

Alright, so now you need to connect to your MySQL server and create a database and user for roundcube.  You can connect by using 'mysql -p'.

Note: Please change $password to a new randomly generated password that you've stored in your password manager.  This will be used during configuration of roundcube.

```sql
CREATE DATABASE roundcubemail;
GRANT ALL PRIVILEGES ON roundcubemail.* TO username@localhost IDENTIFIED BY '$password';
FLUSH PRIVILEGES;
```

Now we need to create the tables and base data for roundcubemail.  Do this by running the following command

```bash
cd /usr/share/nginx/www/roundcube
mysql -p roundcubemail < SQL/mysql.initial.sql
```

Now fix some directory permissions for roundcube

```bash
cd /usr/share/nginx/www/roundcube
chmod 664 temp/
chmod 664 logs/
chown root:www-data logs/
```

Now we need to set the roundcube site to be enabled in nginx and bounce services.

```bash
cd /etc/nginx/sites-enabled/
rm -f default
ln -s /etc/nginx/sites-available/roundcube roundcube
service php-fpm restart
service nginx restart
```

Finally you need to run the installer script for roundcube and follow along with the instructions.  Open a web browser and point it to http://yourdomain/installer/  When you have completed it, remember to remove the installer folder for security.

```bash
cd /usr/share/nginx/www/roundcube
rm -rf installer/
```


Final Server Hardening and Firewall adjustments
----------------------

Note: There are just a few final steps to take that are good security ideas.  There's certainly a lot more that can be done to secure the server with things like grsecurity+selinux kernels, etc. but for the scope of this tutorial with these final steps you should be in pretty good shape.  I may add additional tutorials later that go even further in depth from a server base matching the final configuration here.

Make /etc/passwd, /etc/shadow, and /etc/group immutable (non-modifiable)
```bash
chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/group
```

Clear your MySQL history
```bash
cd ~
cat /dev/null > .mysql_history
```

Allow access to your mailserver and webserver through the firewall
```bash
ufw allow http
ufw allow https
ufw allow imaps
ufw allow smtp
ufw allow submission
ufw allow smtps
```

When you're finished you can type 'ufw status verbose' and you should see the following:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing)
New profiles: skip

To                         Action      From
--                         ------      ----
22                         ALLOW IN    Anywhere
Anywhere                   ALLOW IN    $yourIP
993                        ALLOW IN    Anywhere
465/tcp                    ALLOW IN    Anywhere
25/tcp                     ALLOW IN    Anywhere
443                        ALLOW IN    Anywhere
80                         ALLOW IN    Anywhere
587                        ALLOW IN    Anywhere
22                         ALLOW IN    Anywhere (v6)
993                        ALLOW IN    Anywhere (v6)
465/tcp                    ALLOW IN    Anywhere (v6)
25/tcp                     ALLOW IN    Anywhere (v6)
443                        ALLOW IN    Anywhere (v6)
80                         ALLOW IN    Anywhere (v6)
587                        ALLOW IN    Anywhere (v6)
```

FIN
---

Congratulations, you've configured a working and secure email server.  

Attention: Now you should verify it works by setting up your client to use IMAPS (port 993) and SMTP w/ STARTTLS (port 587) on your mailserver.  Send an email to your existing email account, then reply to it.  Verify you can send successfully and that you can recieve the reply. Verify you can login to webmail using your email username and password.  If everything checks out, you are good to go.


Comments
--------

[gimmick:Disqus](tristor)
