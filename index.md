#Securing Your Email

## Please note, these instructions are no longer maintained.
### You are welcome to still follow them, however you should do independent research before doing so as the instructions may not account for new security issues that exist in the wild.
### [Proton Mail](https://protonmail.com/) has now officially launched and I recommend it for anyone who doesn't want the hassle.
### In most cases, they will probably be more secure than your own implementation based on these instructions.

In the wake of all the news surrounding the NSA's illegal spying activities on US citizens and people around the world and the reality that almost all free email systems propose the tradeoff where you turn over information about the services you subscribe to and the social networks and relationships you keep for their service, it's important that people take control of their communications channels and work towards securing them.  This website attempts to be a relatively comprehensive tutorial on configuring a suite of tools, both server and client, to make this possible.

Note: The material on this site is presented in as straightforward a manner as possible, but assumes that you are capable of doing research on anything you do not understand as you follow the tutorials.  Basic Linux/UNIX administration skills are strongly recommended for following the server portions.


Software Used
-------------

There is a significant amount of software used to make the objectives here-in possible, all of which is free (as in beer) and open-source.  All of the software used here-in is available in the package repositories for Debian and Ubuntu, which is what this guide is based around.  Here is a list of what is being used and in which sections with links to the project websites.  These are not listed in any particular order.

#### Used in Building the Server

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


#### Used in Building the Client

* [Mozilla Thunderbird](https://www.mozilla.org/en-US/thunderbird/)
* [GnuPG](https://www.gnupg.org/)
* [Enigmail](https://www.enigmail.net/home/index.php)
* [Google Chrome](https://www.google.com/intl/en-US/chrome/browser/)



Documentation References
------------------------

My goal with this website is to save you the time and trouble of researching all of this stuff yourself.  I spent the better part of a week reading through documentation about best practices, troubleshooting issues that I encountered, and setting up a working environment of my own mostly following the same steps in my guides.  Below is a list of blog posts and documentation I found exceptionally helpful in this process, some of which contains other attempts at supplying a guide for the same or similar objectives.  Thanks for all of those listed or not who provided helpful information publicly online.  Google-fu helped me in this process more than once.

* [Drew Crawford's Tutorial "NSA-proof your email in 2 hours"](http://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/)
* [OpenPGP Best Practices](https://help.riseup.net/en/gpg-best-practices)
* [The Official Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-howto/)
* [GreenSQL's MySQL Security Best Practices](http://www.greensql.com/content/mysql-security-best-practices-hardening-mysql-tips)
* [The Enigmail Quick Start Guide](https://www.enigmail.net/documentation/quickstart.php)
* [madboa's GPG Quick Start Guide](http://www.madboa.com/geek/gpg-quickstart/)
* [duraconf: Hardened configs for SSL/TLS](https://github.com/ioerror/duraconf)
* [Debian Mempo Project: Hardened Security and Privacy](http://mempo.org/)
* [Strengthening Encrypted Private SSH Keys](https://pthree.org/2013/05/27/strengthen-your-private-encrypted-ssh-keys/)
* [Postfix TLS Perfect Forward Secrecy](http://www.postfix.org/FORWARD_SECRECY_README.html)
* [Best Practical SSL Config](http://www.internetstaff.com/blog/best-practical-ssl-configuration/)
* [Dovecot TLS Perfect Forward Secrecy](https://sys4.de/en/blog/2013/08/15/dovecot-tls-perfect-forward-secrecy/)
* [DNSBL and Greylisting Hybrid Approach](http://www.danplanet.com/blog/2010/09/01/a-dnsbl-and-greylisting-hybrid-approach/)


Feedback & Contacting Me
------------------------

Last but not least, please feel free to provide me any feedback you may have about this site or ask any questions if you encounter a problem.  I cannot promise that I will be able to answer quickly, but I will attempt to help anybody that encounters problems when following my guide.  Each page on this website is Disqus enabled, and if you wish to email me you can do so at tristor@tristor.ro  I greatly prefer email I receive to be signed and/or encrypted, so please make use of my [OpenPGP key](http://keypolicy.tristor.ro/key/tristor.asc).

[gimmick:Disqus](tristor)

