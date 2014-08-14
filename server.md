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

```
apt-get update
apt-get upgrade -y
```

### Upgrade Your Kernel


Note: If you're an advanced user and want additional security, you should considering [installing a grsecurity](https://en.wikibooks.org/wiki/Grsecurity/Obtaining_grsecurity) enabled kernel.  This is a pretty laborious process, although on some platforms can be simplified by making use of [Debian Mempo](http://deb.mempo.org).  


We will install the latest kernel from backports

```
apt-get -t wheezy-backports install linux-image-amd64
```

### Change Your Root Password and Create a User

I advise using a password manager in general.  If you use one, use the random password generator function of it to make a root password that's at least 32 characters long, and store it in the password manager.  You won't need it shortly after we finish our initial configuration.

Replace $username with whatever you want your normal user account to be.  Note, it's being added to the sudoers group.

```
passwd
useradd -m -U -G sudo -s /bin/bash $username
```

### Basic SSH hardening

#####Generate SSH Keys

If you haven't already done so, you need to generate an SSH keypair to use for public-key authentication.  Below is a way to do this that has the advantage of making use of PKCS#8 private key encryption for further hardening.

The tool for generating keys is interactive, so you can follow the prompts.  It's highly recommended to use a descriptive name for your key, as we'll be adding it to the ssh-agent anyway.  So rather than ~/.ssh/id_rsa, I'd recommend ~/.ssh/id_myname.  In this version we'll be using a 4096-bit RSA key for best security.

When enabling PKCS#8, this ONLY for the private key.  Leave the public key unchanged.  ALWAYS set a strong passphrase for your SSH private keys.  Once again, this is a great use case for a password manager.

Run the following from your local client system:

```
ssh-keygen -t rsa -b 4096 
mv ~/.ssh/id_rsa ~/.ssh/id_rsa.old
umask 0077
openssl pkcs8 -topk8 -v2 3des -in ~/.ssh/id_rsa.old -out ~/.ssh/id_rsa
```

If your new key works in the next step, or still works on an existing system you used to login to, you can delete the old key.


##### Put Your Public Key on the Server


Attention: BEFORE making changes to disable password authentication ensure you've copied your SSH public key into the ~/.ssh/authorized_keys file in the home directory of your user on the server.  There is a tool call ssh-copy-id on many systems that will help you do this.  If you must do it manually, that is okay too, see immediately below for instructions.


Run the following from your client system:

```
scp ~/.ssh/id_rsa.pub $username@example.com:~
```

Run the following from your server as your user:

```
mkdir .ssh
chmod 700 .ssh
cd .ssh
touch authorized_keys
chmod 600 authorized_keys
cat ~/id_rsa.pub >> authorized_keys
rm ~/id_rsa.pub
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

```
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

```
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

```
apt-get install -y ufw
```

Configure ufw for SSH

```
ufw default deny incoming
ufw allow ssh
ufw allow from $yourip
ufw enable
```

Hint: If you want to be even more secure, use default deny outgoing as well and enable only outgoing ports you need to specific IPs.  Such as ufw allow out to 8.8.8.8 port 53.  This does require much more effort though.  A future update of this guide may take this into account.

Hint: If you wish to be more secure, limit access to the SSH ports to only your IP by doing ufw allow from $yourip to any port 22.  Just be aware that this limits your flexibility and may be problematic if you only have your home IP in there, since your home connection probably has a dynamic IP.



### Enable Automatic Security Updates

We'll enable automatic security updates using unattended-upgrades and some APT settings.


```
apt-get install -y unattended-upgrades
```

Ensure /etc/apt/apt.conf.d/10periodic has the following:

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


