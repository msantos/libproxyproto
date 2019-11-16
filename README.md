# NAME

libproxyproto - LD\_PRELOAD library for adding support for proxy protocol v2

# SYNOPSIS

* server

LD\_PRELOAD=libproxyproto.so *COMMAND* *ARG* *...*

* test client

LD\_PRELOAD=libproxyproto\_connect.so *COMMAND* *ARG* *...*

# DESCRIPTION

libproxyproto provides a method for applications to discover the original
client IP adddress and port of proxied connections. The application must
be dynamically linked.

The intermediary proxies add a binary protocol header before the
application data using proxy protocol v2:

    https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt

When the connection is `accept(2)`'ed, libproxyproto:

* intercepts the call to `accept(2)`
* reads the proxy protocol header
* sets the source IP address and port in `struct sockaddr` argument of
  `accept(2)`

libproxyproto\_connect does the same thing for `connect(2)` and can be
used for testing.

# ENVIRONMENT VARIABLES

## common

`LIBPROXYPROTO_DEBUG`
: Write errors to stdout (default: disabled).

## libproxyproto

`LIBPROXYPROTO_PROTOCOL_HEADER_IS_OPTIONAL`
: Allow connections with and without the proxy protocol header. This
  option must not be used to support untrusted clients (default: disabled).

`LIBPROXYPROTO_VERSION`
: Supported proxy protocol version (default: 3):

    0: proxy protocol disabled
    1: proxy protocol v1 only
    2: proxy protocol v2 only
    3: proxy protocol v1 and v2

## libproxyproto_connect

`LIBPROXYPROTO_ADDR`
: Source IP address (default: 127.0.0.1)

`LIBPROXYPROTO_PORT`
: Source port (default: 1234)

`LIBPROXYPROTO_VERSION`
: Supported proxy protocol version (default: 3):

    0: proxy protocol disabled
    1: proxy protocol v1
    2: proxy protocol v2

# EXAMPLES

## netcat

```
# run in a shell
LD_PRELOAD=libproxyproto.so nc -vvvv -k -l 9090

# in another shell
LD_PRELOAD=libproxyproto_connect.so \
 LIBPROXYPROTO_ADDR="8.8.8.8" LIBPROXYPROTO_PORT="4321" \
 nc 127.0.0.1 9090
```

## haproxy.conf

```
defaults
    mode tcp
    timeout connect 4s
    timeout client 30s
    timeout server 30s

listen example
    bind <ipaddr>:8080
    server test <ipaddr>:8080 send-proxy-v2
```

# ALTERNATIVES

* [proxyproto.nim](https://github.com/ba0f3/proxyproto.nim)

# SEE ALSO

_connect_(2), _accept_(2)
