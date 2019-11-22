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

#include <unistd.h>

#include "strtonum.h"

void _init(void);
int (*sys_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
#pragma GCC diagnostic ignored "-Wpedantic"
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
#pragma GCC diagnostic warning "-Wpedantic"
int read_evt(int fd, struct sockaddr *from, socklen_t *fromlen);

const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

char *debug;
char *protocol_header_is_optional;
int version = 3;

void _init(void) {
  const char *err;
  char *env_version;

  debug = getenv("LIBPROXYPROTO_DEBUG");
  protocol_header_is_optional =
      getenv("LIBPROXYPROTO_PROTOCOL_HEADER_IS_OPTIONAL");
  env_version = getenv("LIBPROXYPROTO_VERSION");

  if (env_version != NULL) {
    version = atoi(env_version);
    if (version > 255)
      version = 255;
    else if (version < 0)
      version = 0;
  }

#pragma GCC diagnostic ignored "-Wpedantic"
  sys_accept = dlsym(RTLD_NEXT, "accept");
#pragma GCC diagnostic warning "-Wpedantic"
  err = dlerror();

  if (err != NULL)
    (void)fprintf(stderr, "libproxyproto:dlsym (accept):%s\n", err);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int fd;

  fd = sys_accept(sockfd, addr, addrlen);
  if (fd < 0)
    return fd;

  if (debug)
    (void)fprintf(stderr, "accepted connection\n");

  if (read_evt(fd, addr, addrlen) <= 0) {
    if (debug)
      (void)fprintf(stderr, "error: not proxy protocol\n");

    if (protocol_header_is_optional)
      goto LIBPROXYPROTO_DONE;

    if (debug)
      (void)fprintf(stderr, "dropping connection\n");

    (void)close(fd);
    errno = ECONNABORTED;
    return -1;
  }

LIBPROXYPROTO_DONE:
  return fd;
}

/* returns 0 if needs to poll, <0 upon error or >0 if it did the job */
int read_evt(int fd, struct sockaddr *from, socklen_t *fromlen) {
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

  ssize_t size, ret;

  do {
    ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);
  } while (ret == -1 && errno == EINTR);

  if (ret == -1)
    return (errno == EAGAIN) ? 0 : -1;

  if (ret >= 16 && memcmp(&hdr.v2, v2sig, 12) == 0 &&
      (hdr.v2.ver_cmd & 0xF0) == 0x20) {
    size = 16 + ntohs(hdr.v2.len);
    if (ret < size)
      return -1; /* truncated or too large header */

    if (from == NULL || !(version & 2))
      goto done;

    switch (hdr.v2.ver_cmd & 0xF) {
    case 0x01: /* PROXY command */
      switch (hdr.v2.fam) {
      case 0x11: /* TCPv4 */
        if (*fromlen < sizeof(struct sockaddr_in))
          return -1;
        if (debug)
          (void)fprintf(stderr, "*** orig addr=%s:%u\n",
                        inet_ntoa(((struct sockaddr_in *)from)->sin_addr),
                        ntohs(((struct sockaddr_in *)from)->sin_port));
        ((struct sockaddr_in *)from)->sin_family = AF_INET;
        ((struct sockaddr_in *)from)->sin_addr.s_addr =
            hdr.v2.addr.ip4.src_addr;
        ((struct sockaddr_in *)from)->sin_port = hdr.v2.addr.ip4.src_port;
        if (debug)
          (void)fprintf(stderr, "*** proxied addr=%s:%u\n",
                        inet_ntoa(((struct sockaddr_in *)from)->sin_addr),
                        ntohs(((struct sockaddr_in *)from)->sin_port));
        goto done;
      case 0x21: /* TCPv6 */
        if (*fromlen < sizeof(struct sockaddr_in6))
          return -1;
        ((struct sockaddr_in6 *)from)->sin6_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)from)->sin6_addr,
               hdr.v2.addr.ip6.src_addr, 16);
        ((struct sockaddr_in6 *)from)->sin6_port = hdr.v2.addr.ip6.src_port;
        goto done;
      }
      /* unsupported protocol, keep local connection address */
      break;
    case 0x00: /* LOCAL command */
      /* keep local connection address for LOCAL */
      break;
    default:
      return -1; /* not a supported command */
    }
  } else if (ret >= 8 && memcmp(hdr.v1.line, "PROXY", 5) == 0) {
    char *end;

    char *str, *token;
    char *saveptr;
    int j;
    unsigned char buf[sizeof(struct in6_addr)] = {0};
    uint16_t port;

    end = memchr(hdr.v1.line, '\r', (size_t)ret - 1);

    if (!end || end[1] != '\n')
      return -1; /* partial or invalid header */

    *end = '\0';                  /* terminate the string to ease parsing */
    size = end + 2 - hdr.v1.line; /* skip header + CRLF */

    if (from == NULL || !(version & 1))
      goto done;

    /* PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535
     * PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535
     * PROXY UNKNOWN
     * PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535
     */
    for (j = 1, str = hdr.v1.line;; j++, str = NULL) {
      token = strtok_r(str, " ", &saveptr);
      if (token == NULL)
        return -1;

      if (debug)
        (void)fprintf(stderr, "v1:%d:%s\n", j, token);

      switch (j) {
      case 1:
        /* PROXY */
        continue;
      case 2:
        /* TCP4, TCP6, UNKNOWN */
        if (strcmp(token, "UNKNOWN") == 0) {
          goto done;
        } else if (strcmp(token, "TCP4") == 0) {
          if (*fromlen < sizeof(struct sockaddr_in))
            return -1;
          ((struct sockaddr_in *)from)->sin_family = AF_INET;
        } else if (strcmp(token, "TCP6") == 0) {
          if (*fromlen < sizeof(struct sockaddr_in6))
            return -1;
          ((struct sockaddr_in6 *)from)->sin6_family = AF_INET6;
        } else {
          return -1;
        }
        break;
      case 3:
        /* source address */
        if (inet_pton(((struct sockaddr *)from)->sa_family, token, buf) != 1) {
          return -1;
        }
        if (((struct sockaddr *)from)->sa_family == AF_INET) {
          ((struct sockaddr_in *)from)->sin_addr.s_addr =
              ((struct in_addr *)buf)->s_addr;
        } else if (((struct sockaddr *)from)->sa_family == AF_INET6) {
          (void)memcpy(hdr.v2.addr.ip6.src_addr, buf, 16);
        }
        break;
      case 4:
        /* destination address */
        if (inet_pton(((struct sockaddr *)from)->sa_family, token, buf) != 1) {
          return -1;
        }
        continue;
      case 5:
        /* source port */
        errno = 0;
        port = (uint16_t)strtonum(token, 0, UINT16_MAX, NULL);
        if (errno)
          return -1;

        if (((struct sockaddr *)from)->sa_family == AF_INET) {
          ((struct sockaddr_in *)from)->sin_port = htons(port);
        } else if (((struct sockaddr *)from)->sa_family == AF_INET6) {
          ((struct sockaddr_in6 *)from)->sin6_port = htons(port);
        }
        break;
      case 6:
        /* destination port */
        errno = 0;
        (void)strtonum(token, 0, UINT16_MAX, NULL);
        if (errno)
          return -1;
        goto done;
      default:
        return -1;
      }
    }
  } else {
    /* Wrong protocol */
    return -1;
  }

done:
  /* we need to consume the appropriate amount of data from the socket */
  do {
    ret = recv(fd, &hdr, (size_t)size, 0);
  } while (ret == -1 && errno == EINTR);
  return (ret >= 0) ? 1 : -1;
}
