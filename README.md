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

Intermediary proxies add a binary protocol header before the application
data using the proxy protocol:

    https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt

Both proxy proxy protocol v1 and v2 are supported.

When the connection is `accept(2)`'ed, libproxyproto:

* intercepts the call to `accept(2)`
* reads the proxy protocol header
* sets the source IP address and port in the `struct sockaddr` argument of
  `accept(2)`

libproxyproto\_connect does the same thing for calls to `connect(2)`
and can be used for testing.

# ENVIRONMENT VARIABLES

## common

`LIBPROXYPROTO_DEBUG`
: Write errors to stderr (default: disabled).

## libproxyproto

`LIBPROXYPROTO_MUST_USE_PROTOCOL_HEADER`
: By default, connections without the proxy protocol header are
  allowed. Enabling this option drops connections without a protocol header
  (default: disabled).

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
: Source port (default: 8080)

`LIBPROXYPROTO_VERSION`
: Supported proxy protocol version (default: 2):

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
# test haproxy
# server: LD_PRELOAD=libproxyproto.so nc -vvvv -k -l 9090
defaults
    mode tcp
    timeout connect 4s
    timeout client 30s
    timeout server 30s

listen example
    bind :8080
    server test 127.0.0.1:9090 send-proxy-v2
```

# ALTERNATIVES

* [proxyproto.nim](https://github.com/ba0f3/proxyproto.nim)

# SEE ALSO

_connect_(2), _accept_(2)
