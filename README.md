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
FREEBIND_RANDOM=2a00:1450:4001:81b::/64 LD_PRELOAD=$(pwd)/bin/freebind.so wget -qO- ipv6.wtfismyip.com/text
```

### Notes
The application will only work if your internet service provider provides you with a routed prefix.
