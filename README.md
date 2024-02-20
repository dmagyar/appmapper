
# What is appmapper?

Appmapper is a tool that attaches to your primary network interface and collects information about and inbound or outbound TCP connections (by looking at SYN packets) as well as maps out DNS recursion to find FQDNs. This is useful if you would like to put a legacy application behind firewalls and you don't really know much about the app itself. Let this run for a few days/weeks and your logfile will show every connection without the need of actual PCAPs or span ports.

# How to use?

For linux just run ``appmapper-linux-install.sh`` from the repo it will deploy a small chroot into a directory of choice. Once complete run ``start.sh`` as root from the installation directory. Output will be shown on screen as well as logged to appmapper.log in the same directory.

## Command line options



|  cmdline 	|   description	|
|---	|---	|
| ``-interface``  	|   Names a specific interface to listen on. <br>Defaults to auto-detection based on default gateway.	|
| ``-allconns`` 	|   Prints all connections and not just once per unique destination/port	|

## Running as root? DANGER!

Unfortunately recording network traffic requires root permissions. Luckily the source code is available so you can check what the tool does exactly before executing it. Or just believe me and take your chances :)

## I have logs now, what now?

Every line is prefixed with a ``[TAG]``  - this indicates either an inbound connection ``[INTCP]`` , an outbound connection ``[OUTTCP]``  or a ``[DNS]`` recursion.  If ``[DNS]``    was recursed for an IP address you will also see the corresponding FQDN on the connection lines. Every TCP SRC-DST-DPORT triplet is only printed once, regardless of connection count. DNS recursions are logged as they happen.
The next tag represents what happened ``ACK``, ``RST`` or ``TIMEOUT`` followed by the observed latency between the initial **SYN** and the response (or lack of in case of a ``TIMEOUT``). This is followed by the ``S: srcip  D:  destip DP: destport`` structure along with any optional FQDNs as recorded from DNS lookups for the destination IP.

## Example Log

```
[HOST] Auto Interface: en0 IP: 10.119.0.149 Gateway: 10.119.0.1
[DNS] poison.hu -> 95.140.46.70
[OUTTCP] ACK(10ms) S:10.119.0.149 D:10.119.0.210 DP:22
[DNS] cnn.com -> 151.101.3.5
[OUTTCP] ACK(10ms) S:10.119.0.149 D:151.101.3.5 DP:80 [cnn.com]
[OUTTCP] ACK(64ms) S:10.119.0.149 D:94.199.52.131 DP:443
[DNS] config.edge.skype.com -> l-0007.l-msedge.net -> 13.107.42.16
[OUTTCP] ACK(21ms) S:10.119.0.149 D:13.107.42.16 DP:443 [config.edge.skype.com]
[DNS] channels.skype.com -> s-0006.s-msedge.net -> 52.113.194.133
[OUTTCP] ACK(20ms) S:10.119.0.149 D:52.113.194.133 DP:443 [channels.skype.com]
[DNS] e6858.dscx.akamaiedge.net -> 2.19.244.246
[DNS] ur.gd -> 88.99.24.46
[OUTTCP] TIMEOUT(1109ms) S:10.119.0.149 D:88.99.24.46 DP:6119 [ur.gd]
[DNS] browser.pipe.aria.microsoft.com -> onedscolprdeus07.eastus.cloudapp.azure.com -> 52.168.117.168
[DNS] browser.pipe.aria.microsoft.com -> onedscolprdeus07.eastus.cloudapp.azure.com -> 52.168.117.168
[OUTTCP] ACK(179ms) S:10.119.0.149 D:52.168.117.168 DP:443 [browser.pipe.aria.microsoft.com]
```


