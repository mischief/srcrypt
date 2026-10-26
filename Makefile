CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -std=gnu11
LIBS = $(shell pkg-config --libs libcrypto devmapper)
CPPFLAGS += $(shell pkg-config --cflags libcrypto devmapper)

OBJS = srcrypt.o bcrypt_pbkdf.o blowfish.o

srcrypt: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

# Upstream code: OpenSSL 3 deprecates SHA512_Init, and the magic string
# fills its array with no NUL on purpose.
bcrypt_pbkdf.o: CFLAGS += -Wno-deprecated-declarations -Wno-unterminated-string-initialization

$(OBJS): compat.h blf.h

clean:
	rm -f srcrypt $(OBJS)

.PHONY: clean
