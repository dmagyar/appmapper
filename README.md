# What is appmapper?

Appmapper is a tool that attaches to your primary network interface and collects information about and inbound or outbound TCP connections (by looking at SYN packets) as well as maps out DNS recursion to find FQDNs. This is useful if you would like to put a legacy application behind firewalls and you don't really know much about the app itself. Let this run for a few days/weeks and your logfile will show every connection without the need of actual PCAPs or span ports.

# How to use?

For linux just run ``appmapper-linux-install.sh`` from the repo it will deploy a small chroot into a directory of choice. Once complete run ``start.sh`` as root from the installation directory. Output will be shown on screen as well as logged to appmapper.log in the same directory.

## Command line options

``-interface <intfname>`` specifies a specific interface to listen on. Defaults to auto-detection based on default gateway.

## Running as root? DANGER!

Unfortunately recording network traffic requires root permissions. Luckily the source code is available so you can check what the tool does exactly before executing it. Or just believe me and take your chances :)

## I have logs now, what now?

Every line is prefixed with a ``[TAG]``  - this indicates either an inbound connection ``[INTCP]`` , an outbound connection ``[OUTTCP]``  or a ``[DNS]`` recursion.  If ``[DNS]``    was recursed for an IP address you will also see the corresponding FQDN on the connection lines. Every TCP SRC-DST-DPORT triplet is only printed once, regardless of connection count. DNS recursions are logged as they happen.

## Example Log

```
[HOST] Interface: en0 IP: 10.119.0.149 Gateway: 10.119.0.1
[OUTTCP] S:10.119.0.149 D:10.119.2.104 DP:80
[DNS] cnn.com -> 151.101.3.5
[OUTTCP] S:10.119.0.149 D:151.101.3.5 DP:80 [cnn.com]
[INTCP] S:10.119.0.210 D:10.119.0.149 DP:22
```


