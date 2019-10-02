# pop_smtp

## Origine

For my email, I usually use mpop (download mail) + neomutt + msmtp (send mail).
I wanted to learn a bit on how pop and smtp protocol work, so I decided to rewrite the mpop and msmtp myself, in Rust.

## Use case

Mine. 
That means, this software have limited functionalities: Only those required for my usecase

## "Goal" 

The goal is to replace mpop and msmtp for my usecase. 
The code base should be as small as possible. 
The code should not contains any functionality unused by me. 

## Config file example ( my config file. Should be ``~/.pop`` )

```
host neowutran.ovh
port 110
tls starttls
user XXX@neowutran.ovh
password qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@neowutran.ovh.asc
maildir ~/Mail/XXX@neowutran.ovh/INBOX/

host neowutran.ovh
port 587
tls starttls
user XXX@neowutran.ovh
password qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@neowutran.ovh.asc

host pop.librem.one
port 995
user XXX@librem.one
password qubes-gpg-client-wrapper --quiet --no-tty --decrypt ~/XXX@librem.one.asc
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
