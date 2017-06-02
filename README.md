# Freebind
Make use of any IP address from a prefix that is routed to your machine.

## Background
With the introduction of IPv6 single machines often get prefixes with more than one IP address assigned. However, without AnyIP and socket freebinding, many applications lack support to dynamically bind to arbitrary unconfigured addresses within these prefixes. Freebind enables the [IP\_FREEBIND](http://man7.org/linux/man-pages/man7/ip.7.html) socket option by hooking into `socket` library calls using `LD_PRELOAD`.

## Usage
### Installing
Clone and `cd` into the git repository, then run `make install`.
### Setup
Assume your ISP has assigned the subnet `2a00:1450:4001:81b::/64` to your server. In order to make use of freebinding, you first need to configure the [Linux AnyIP kernel feature](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ab79ad14a2d51e95f0ac3cef7cd116a57089ba82) in order to be able to bind a socket to an arbitrary IP address from this subnet as follows:

```
ip -6 route add local 2a00:1450:4001:81b::/64 dev lo
```

### Example
Having set up AnyIP, the following command will bind wget's internal socket to a random address from the specified subnet:
```
freebind -r 2a00:1450:4001:81b::/64 wget -qO- ipv6.wtfismyip.com/text
```

### UDP per packet randomization
The `freebind` program is only suitable for assigning one IP address per socket. It will not assign a random IP address per packet. Therefore, `packetrand` making use of the netfilter API is included for use in scenarios that require a fresh IP address per outgoing packet.

#### Setup
Imagine you want to randomize source addresses for DNS resolving. The following command has `iptables` pass outgoing DNS packets to the `packetrand` userspace program:
```
ip6tables -I OUTPUT -j NFQUEUE -p udp --dport 53 --queue-num 0 --queue-bypass
```
Afterwards, `packetrand` could be invoked as follows, where 0 is the netfilter queue number:
```
packetrand 0 2a00:1450:4001:81b::/64
```
This will cause `packetrand` to rewrite the source address of outgoing packets to a random address from the specified prefix. Because incoming reply packets will be sent to the random source address, we need `iptables` to translate the address back in order for the packet to be passed to the origin socket again, assuming that the socket is bound to `2a00:1450:4001:81b::`:
```
ip6tables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination [2a00:1450:4001:81b::]:53
```

### Limitations
- IPv6 extension headers are not yet supported
- IPv4 checksumming is not yet supported at all

### Notes
The application will only work if your internet service provider provides you with a routed prefix.
