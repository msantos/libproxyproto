# NAME

libproxyproto - LD\_PRELOAD library for adding support for proxy protocol v1 and v2

# SYNOPSIS

* server

LD\_PRELOAD=libproxyproto.so *COMMAND* *ARG* *...*

* test client

LD\_PRELOAD=libproxyproto\_connect.so *COMMAND* *ARG* *...*

# DESCRIPTION

libproxyproto provides a method for applications to discover the original
client IP adddress and port of proxied connections. The application must
be dynamically linked.

Intermediary proxies insert the proxy protocol header before the application
data:

    https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt

Proxy protocol v1 and v2 are supported.

When the connection is `accept(2)`'ed, libproxyproto:

* intercepts the call to `accept(2)`
* reads the proxy protocol header
* sets the source IP address and port in the `struct sockaddr` argument of
  `accept(2)`
* caches the IP address and intercepts calls to `getpeername(2)`

libproxyproto\_connect does the same thing for calls to `connect(2)`
and can be used for testing.

# ENVIRONMENT VARIABLES

## common

`LIBPROXYPROTO_DEBUG`
: Write errors to stderr (default: disabled)

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

### IPv6

```
# run in a shell
LD_PRELOAD=libproxyproto.so nc -vvvv -n -6 -k -l 9090

# in another shell
LD_PRELOAD=libproxyproto_connect.so \
 LIBPROXYPROTO_ADDR="2001:4860:4860::8888" LIBPROXYPROTO_PORT="4321" \
 nc -6 -v localhost 9090
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

# BENCHMARK

To give a very rough idea of the overhead, a
[benchmark](https://github.com/path-network/go-mmproxy/blob/master/README.md#benchmark)
was run against an echo service.

This benchmark is not meant to be conclusive:

* run over the loopback
* on an old system running many other services

## Benchmark Client

[tcpkali](https://github.com/satori-com/tcpkali)

```
tcpkali -c 50 -T 10s -e1 'PROXY TCP4 127.0.0.1 127.0.0.1 \{connection.uid} 25578\r\n' -m 'PING\r\n' 127.0.0.1:1122
```

## Echo Server

To run:

    erlc echo.erl

    # no proxy: run on port 1122
    erl -noshell -eval "echo:start()"

    # libproxyproto: run on port 1122
    LD_PRELOAD=libproxyproto.so erl -noshell -eval "echo:start()"

    # go-mmproxy: run on port 1123
    erl -noshell -eval "echo:start(1123)"
    sudo ./go-mmproxy -l 0.0.0.0:1122 -4 127.0.0.1:1123


``` erlang
-module(echo).

-export([start/0, start/1]).

start() ->
    start(1122).

start(Port) ->
    {ok, S} = gen_tcp:listen(Port, [
        binary,
        {reuseaddr, true},
        {backlog, 1024}
    ]),
    accept(S).

accept(LS) ->
    {ok, S} = gen_tcp:accept(LS),
    Pid = spawn(fun() -> recv(S) end),
    _ = gen_tcp:controlling_process(S, Pid),
    accept(LS).

recv(S) ->
    receive
        {tcp, S, Data} ->
            gen_tcp:send(S, Data),
            recv(S);
        {tcp_closed, S} ->
            ok;
        Error ->
            error_logger:error_report([{socket, S}, {error, Error}])
    end.
```

## Results

|          | ⇅ Mbps | ↓ Mbps | ↑ Mbps |  ↓ pkt/s | ↑ pkt/s |
|----------|---------|--------|--------|----------|---------|
| noproxy       | 98.238 | 2455.263 | 2456.626 | 229245.6 | 210847.5 |
| libproxyproto | 94.974 | 2373.474 | 2375.247 | 221341.9 | 203862.9 |
| go-mmproxy    | 76.567 | 1901.043 | 1927.293 | 163515.0 | 165415.9 |

Bandwidth per channel: ⇅ Mbps
Aggregate bandwidth: ↓, ↑ Mbps
Packet rate estimate: ↓, ↑

# SEE ALSO

_connect_(2), _accept_(2), _getpeername_(2)
