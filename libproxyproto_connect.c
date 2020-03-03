/* Copyright (c) 2019, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <unistd.h>

void _init(void);
int (*sys_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#pragma GCC diagnostic ignored "-Wpedantic"
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#pragma GCC diagnostic warning "-Wpedantic"
int write_evt(int fd, void *from, uint16_t port, const struct sockaddr *to,
              socklen_t tolen);
int write_v1(int fd, void *from, uint16_t port, const struct sockaddr *to,
             socklen_t tolen);
int write_v2(int fd, void *from, uint16_t port, const struct sockaddr *to,
             socklen_t tolen);

const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

char *debug;
char *paddr;
uint16_t pport;
int version = 2;

void _init(void) {
  const char *err;
  char *env_port;
  char *env_version;

  debug = getenv("LIBPROXYPROTO_DEBUG");

  paddr = getenv("LIBPROXYPROTO_ADDR");
  if (paddr == NULL)
    paddr = "127.0.0.1";

  env_version = getenv("LIBPROXYPROTO_VERSION");
  if (env_version != NULL) {
    version = atoi(env_version);
    if (version < 0 || version > 2)
      _exit(111);
  }

  env_port = getenv("LIBPROXYPROTO_PORT");
  pport = htons((uint16_t)atoi(env_port ? env_port : "8080"));

#pragma GCC diagnostic ignored "-Wpedantic"
  sys_connect = dlsym(RTLD_NEXT, "connect");
#pragma GCC diagnostic warning "-Wpedantic"
  err = dlerror();

  if (err != NULL)
    (void)fprintf(stderr, "libproxyproto:dlsym (connect):%s\n", err);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int fd;
  int oflags;
  int nflags = 0;
  unsigned char buf[sizeof(struct in6_addr)];

  oflags = fcntl(sockfd, F_GETFL);
  if (oflags < 0)
    goto LIBPROXYPROTO_CONNECT;

  nflags = oflags & ~O_NONBLOCK;

  if (oflags != nflags) {
    if (fcntl(sockfd, F_SETFL, nflags) < 0)
      goto LIBPROXYPROTO_CONNECT;
  }

LIBPROXYPROTO_CONNECT:
  fd = sys_connect(sockfd, addr, addrlen);
  if (fd < 0)
    return fd;

  if (debug)
    (void)fprintf(stderr, "connected\n");

  switch (((const struct sockaddr *)addr)->sa_family) {
  case AF_INET:
    if (inet_pton(AF_INET, paddr, buf) != 1) {
      if (debug)
        (void)fprintf(stderr, "error: invalid address\n");
      goto LIBPROXYPROTO_DONE;
    }
    break;
  case AF_INET6:
    if (inet_pton(AF_INET6, paddr, buf) != 1) {
      if (debug)
        (void)fprintf(stderr, "error: invalid address\n");
      goto LIBPROXYPROTO_DONE;
    }
    break;
  default:
    goto LIBPROXYPROTO_DONE;
    break;
  }

  if (write_evt(sockfd, buf, pport, (const struct sockaddr *)addr, addrlen) <
      0) {
    if (debug)
      (void)fprintf(stderr,
                    "error: proxy protocol not supported for socket type\n");
  }

LIBPROXYPROTO_DONE:
  if (oflags != nflags) {
    if (fcntl(sockfd, F_SETFL, oflags) < 0)
      _exit(111);
  }

  return fd;
}

int write_evt(int fd, void *from, uint16_t port, const struct sockaddr *to,
              socklen_t tolen) {
  switch (version) {
  case 0:
    return 1;
  case 1:
    return write_v1(fd, from, port, to, tolen);
  case 2:
    return write_v2(fd, from, port, to, tolen);
  default:
    return -1;
  }
}

int write_v1(int fd, void *from, uint16_t port, const struct sockaddr *to,
             socklen_t tolen) {
  char buf[108] = {0};
  char saddr[INET6_ADDRSTRLEN] = {0};
  char daddr[INET6_ADDRSTRLEN] = {0};
  uint16_t size = 0;
  ssize_t ret;
  int rv;

  switch (((const struct sockaddr *)to)->sa_family) {
  case AF_INET:
    if (tolen < sizeof(struct sockaddr_in))
      return -1;

    if (inet_ntop(AF_INET, &(((struct in_addr *)from)->s_addr), saddr,
                  INET_ADDRSTRLEN) == NULL)
      return -1;

    if (inet_ntop(AF_INET, &(((const struct sockaddr_in *)to)->sin_addr.s_addr),
                  daddr, INET_ADDRSTRLEN) == NULL)
      return -1;

    rv = snprintf(buf, sizeof(buf), "PROXY TCP4 %s %s %u %u\r\n", saddr, daddr,
                  ntohs(port),
                  ntohs(((const struct sockaddr_in *)to)->sin_port));

    break;
  case AF_INET6:
    if (tolen < sizeof(struct sockaddr_in6))
      return -1;

    if (inet_ntop(AF_INET6, from, saddr, INET6_ADDRSTRLEN) == NULL)
      return -1;

    if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)to)->sin6_addr,
                  daddr, INET6_ADDRSTRLEN) == NULL)
      return -1;

    rv = snprintf(buf, sizeof(buf), "PROXY TCP6 %s %s %u %u\r\n", saddr, daddr,
                  ntohs(port),
                  ntohs(((const struct sockaddr_in6 *)to)->sin6_port));

    break;
  default:
    return -1;
  }

  if (rv <= 0 || rv > (int)sizeof(buf))
    return -1;

  size = (uint16_t)rv;

  while ((ret = write(fd, buf, size)) == -1 && errno == EINTR)
    ;

  return ret == size ? 1 : -1;
}

int write_v2(int fd, void *from, uint16_t port, const struct sockaddr *to,
             socklen_t tolen) {
  union {
    struct {
      char line[108];
    } v1;
    struct {
      uint8_t sig[12];
      uint8_t ver_cmd;
      uint8_t fam;
      uint16_t len;
      union {
        struct { /* for TCP/UDP over IPv4, len = 12 */
          uint32_t src_addr;
          uint32_t dst_addr;
          uint16_t src_port;
          uint16_t dst_port;
        } ip4;
        struct { /* for TCP/UDP over IPv6, len = 36 */
          uint8_t src_addr[16];
          uint8_t dst_addr[16];
          uint16_t src_port;
          uint16_t dst_port;
        } ip6;
        struct { /* for AF_UNIX sockets, len = 216 */
          uint8_t src_addr[108];
          uint8_t dst_addr[108];
        } unx;
      } addr;
    } v2;
  } hdr;

  uint16_t size;
  ssize_t ret;

  (void)memcpy(hdr.v2.sig, v2sig, sizeof(hdr.v2.sig));
  hdr.v2.ver_cmd = 0x21;

  switch (((const struct sockaddr *)to)->sa_family) {
  case AF_INET:
    if (tolen < sizeof(struct sockaddr_in))
      return -1;
    hdr.v2.fam = 0x11;
    size = 16 + 12;
    hdr.v2.len = htons(12);
    hdr.v2.addr.ip4.src_addr = ((struct in_addr *)from)->s_addr;
    hdr.v2.addr.ip4.src_port = port;
    hdr.v2.addr.ip4.dst_addr =
        ((const struct sockaddr_in *)to)->sin_addr.s_addr;
    hdr.v2.addr.ip4.dst_port = ((const struct sockaddr_in *)to)->sin_port;
    break;
  case AF_INET6:
    if (tolen < sizeof(struct sockaddr_in6))
      return -1;
    hdr.v2.fam = 0x21;
    size = 16 + 36;
    hdr.v2.len = htons(36);
    memcpy(hdr.v2.addr.ip6.src_addr, from, 16);
    hdr.v2.addr.ip6.src_port = port;
    memcpy(hdr.v2.addr.ip6.dst_addr,
           &((const struct sockaddr_in6 *)to)->sin6_addr, 16);
    hdr.v2.addr.ip6.dst_port = ((const struct sockaddr_in6 *)to)->sin6_port;
    break;
  default:
    return -1;
  }

  while ((ret = write(fd, &hdr.v2, size)) == -1 && errno == EINTR)
    ;

  return ret == size ? 1 : -1;
}
