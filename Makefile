.PHONY: all clean

all: libproxyproto libproxyproto_connect

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), OpenBSD)
	LIBPROXYPROTO_LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
else
	LIBPROXYPROTO_LDFLAGS ?= -ldl -Wl,-z,relro,-z,now -Wl,-z,noexecstack
endif

libproxyproto:
	$(CC) -Wall -Wextra -pedantic -D_GNU_SOURCE -nostartfiles -shared -fpic -fPIC \
		-Wconversion -Wshadow \
		-Wpointer-arith -Wcast-qual \
		-Wstrict-prototypes -Wmissing-prototypes \
	 	-o $@.so $@.c strtonum.c \
	 	$(LIBPROXYPROTO_LDFLAGS)

libproxyproto_connect:
	$(CC) -Wall -Wextra -pedantic -D_GNU_SOURCE -nostartfiles -shared -fpic -fPIC \
		-Wconversion -Wshadow \
		-Wpointer-arith -Wcast-qual \
		-Wstrict-prototypes -Wmissing-prototypes \
	 	-o $@.so $@.c \
	 	$(LIBPROXYPROTO_LDFLAGS)

clean:
	-@rm libproxyproto.so libproxyproto_connect.so
