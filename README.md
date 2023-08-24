# Freebind
Make use of any IP address from a prefix that is routed to your machine.

With the introduction of IPv6, single machines often get prefixes with more than one IP address assigned. However, without AnyIP and socket freebinding, many applications lack support to dynamically bind to arbitrary unconfigured addresses within these prefixes. Freebind enables the [IP\_FREEBIND](http://man7.org/linux/man-pages/man7/ip.7.html) socket option by hooking into `socket` library calls using `LD_PRELOAD`.

IPv6 services employing rate limiting often ban per /128 or per /64 in order to minimize collateral damage. If you have a statically routed prefix that is smaller than the prefix being banned, you can make use of freebind, which will bind sockets to random IP addresses from specified prefixes.

## Usage
### Installing
Clone and `cd` into the git repository, then run `make install`. In order for `packetrand` to be built successfully, `libnetfilter-queue-dev` is required.
### Setup
Assume your ISP has assigned the subnet `2a00:1450:4001:81b::/64` to your server. In order to make use of freebinding, you first need to configure the [Linux AnyIP kernel feature](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ab79ad14a2d51e95f0ac3cef7cd116a57089ba82) in order to be able to bind a socket to an arbitrary IP address from this subnet as follows:

```
ip -6 route add local 2a00:1450:4001:81b::/64 dev lo
```

### Example
Having set up AnyIP, the following command will bind wget's internal socket to a random address from the specified subnet:
```
freebind -r 2a00:1450:4001:81b::/64 -- wget -qO- ipv6.wtfismyip.com/text
```
In practice, running this command multiple times will yield a new IP address every time.

#### Crawling with curl
You can use new versions of curl (tested with 7.87.0) with freebind to bypass web server rate limits as follows:
```
freebind -r 2a00:1450:4001:81b::/64 -- curl --http1.1 -6 -H "Connection: close" --parallel --parallel-immediate --parallel-max 100 --config config.txt
```
In the above example, `config.txt` contains the URLs you wish to crawl in the curl config format, e.g. `url = "https://ipv6.wtfismyip.com/text"`. Consult the curl man page for more information on the format. Since curl cannot be explicitly configured to use a new socket for each request, we leverage the `Connection: close` header, which is only supported by HTTP/1.1. Alternatively, HTTP/1.0 could be used.

Note that freebind does not work with statically linked binaries in general, including those that can be downloaded from the curl website.

### UDP per packet randomization
The `freebind` program is only suitable for assigning one IP address per socket. It will not assign a random IP address per packet. Therefore, `packetrand` making use of the netfilter API is included for use in scenarios that require a fresh IP address per outgoing packet.

#### Setup
Imagine you want to randomize source addresses for DNS resolving. The following command has `iptables` pass outgoing DNS packets to the `packetrand` userspace program:
```
ip6tables -I OUTPUT -j NFQUEUE -p udp --dport 53 --queue-num 0 --queue-bypass
ip6tables -I INPUT -j NFQUEUE -p udp --sport 53 --queue-num 0 --queue-bypass
```
Afterwards, the `packetrand` daemon could be invoked as follows, where 0 is the netfilter queue number:
```
packetrand 0 2a00:1450:4001:81b:: 2a00:1450:4001:81b::/64
```
This will cause `packetrand` to rewrite the source address of outgoing packets to a random address from the specified prefix and translate back the destination address of incoming packets to `2a00:1450:4001:81b::` which is supposed to be the address which the socket is bound to.

#### Source port randomization
You can use the `-r` switch in order to randomize source ports per packet.
```
packetrand 0 -r 53
```
In this case, all outgoing UDP packets that are handled by the queue have their source port randomized and 53 is the port number for incoming packets to be rewritten to.

#### Limitations
- IPv6 extension headers are not yet supported

### References
- [The scary state of IPv6 rate-limiting, A. Pritchard, 2022](https://adam-p.ca/blog/2022/02/ipv6-rate-limiting/)
- [Exploring The State of Rate Limiting in IPv6, P. Heijningen, 2023](http://essay.utwente.nl/96014/1/van%20Heijningen_BA_EEMCS.pdf)

### Notes
The application will only work if your internet service provider provides you with a routed prefix.
