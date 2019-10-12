# pop_smtp

## Origine

For my email, I usually use mpop (download mail) + neomutt + msmtp (send mail).
I wanted to learn a bit on how pop and smtp protocol work, so I decided to replace mpop and msmtp.

## Use case

Mine. 
That means, this software have limited functionalities: Only those required for my usecase

## "Goal" 

The goal is to replace mpop ( https://marlam.de/mpop/ ) and msmtp ( https://marlam.de/msmtp/ ), for my usecase. 
The code base should be as small as possible. 
The code should not contains any functionality unused by myself. 

## Config file example ( my config file. Should be ``~/.pop`` )

```
host neowutran.ovh
port 110
tls starttls
user XXX@neowutran.ovh
password /usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@neowutran.ovh.asc
maildir ~/Mail/XXX@neowutran.ovh/INBOX/

host neowutran.ovh
port 587
tls starttls
user XXX@neowutran.ovh
password /usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@neowutran.ovh.asc

host pop.librem.one
port 995
user XXX@librem.one
password /usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@librem.one.asc
maildir ~/Mail/XXX@librem.one/INBOX/
```

## How to use

### Download email

```
./pop_smtp
```

### Send email ( mutt config ) 

```
set sendmail = "/home/user/pop_smtp -a XXX@neowutran.ovh"
```

## Current statut

It work for my usecase.

## Security Information

In the config file, both parameter ``password`` and ``maildir`` are directly used as shell command without any restriction. This is the intended behavior for ``password``, and this is a behavior I do not care about for ``maildir``. 

That means that if an attacker have a write access to the config file, the attacker can take over your VM ( or computer if you don't use it in a VM). 
That also means that you MUST NOT use a config file you found on the internet without reading its content.

If someone want to try to reduce the risk of the ``password`` and ``maildir`` parameter: you can hardcode the command used for ``password`` and reduce the possibilities for ``maildir`` (example: ``/usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/{}.asc``). But keep in mind that if an attacker can modify your config file, he can steal your password by just modifying the ``host`` to point to a server that he own.

In my specific usecase, this software is run in a "AppVM" that only contains my mail. So the biggest damage that one could try to do is stealing my email password. So I didn't tryied to reduce the attack surface of the field ``password`` and ``maildir``.
