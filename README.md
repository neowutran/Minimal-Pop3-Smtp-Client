# Minimal Pop3 Smtp Client

## Origin

For my email, I used mpop (download mail) + neomutt + msmtp (send mail).
I wanted to learn a bit on how pop and smtp protocol work, so I decided to write my own replacement mpop and msmtp.

## Use case

This software have limited functionalities: Only those required for my usecase

## "Goal" 

The goal was to replace mpop ( https://marlam.de/mpop/ ) and msmtp ( https://marlam.de/msmtp/ ) in my mail setup. 
The code base should be as small as possible.

## Config file example ( my config file. Should be ``/home/user/.pop_smtp`` )

```
host neowutran.ovh
port 110
tls starttls
user XXX@neowutran.ovh
protocol pop

host neowutran.ovh
port 587
tls starttls
user XXX@neowutran.ovh
protocol smtp

host pop.librem.one
port 995
user XXX@librem.one
protocol pop
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

**It work** and I use it everyday.
Support for "login" authentication method. 
Support for TLS and StartTLS. 
Support for Qubes OS only. 
Read the source code for more details, it is small.
