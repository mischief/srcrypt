/* Map OpenBSD libc names used by the vendored files onto Linux and libcrypto. */
#ifndef SRCRYPT_COMPAT_H
#define SRCRYPT_COMPAT_H

#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#define DEF_WEAK(x)

#define SHA2_CTX		SHA512_CTX
#define SHA512Init(c)		SHA512_Init(c)
#define SHA512Update(c, d, l)	SHA512_Update((c), (d), (l))
#define SHA512Final(o, c)	SHA512_Final((o), (c))

int	bcrypt_pbkdf(const char *, size_t, const uint8_t *, size_t,
	    uint8_t *, size_t, unsigned int);

#endif
