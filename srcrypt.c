/* SPDX-License-Identifier: ISC */
/*
 * Copyright (c) 2026 Nick Owens <mischief@offblast.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

/*
 * srcrypt: open OpenBSD softraid CRYPTO volumes on Linux with dm-crypt.
 * Unwrap the disk keys with the passphrase or keydisk, load a read-only
 * dm-crypt table, and add one read-only dm-linear device per partition.
 */

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <libdevmapper.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "compat.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "metadata is read in host order; only little-endian hosts are supported"
#endif

#define DEV_BSIZE		512

#define SR_MAGIC		0x4d4152436372616dULL
#define SR_META_SIZE		64
#define SR_META_OFFSET		16
#define SR_META_V3_DATA_OFFSET	80
#define SR_DATA_OFFSET		528
#define SR_KEYDISK_LEVEL	0xfffffffe
#define SR_CRYPTO_LEVEL		'C'

#define SR_OPT_CRYPTO		1
#define SR_OPT_KEYDISK		3
#define SR_OLD_META_OPT_SIZE	2480
#define SR_OLD_META_OPT_OFFSET	8

#define SR_CRYPTO_MAXKEYS	32
#define SR_CRYPTO_KEYBYTES	64
#define SR_CRYPTO_MASKBYTES	32
#define SR_CRYPTO_KEY_BLKSHIFT	30

#define SR_CRYPTOA_AES_XTS_128	1
#define SR_CRYPTOA_AES_XTS_256	2
#define SR_CRYPTOF_KEY		(1 << 0)
#define SR_CRYPTOF_KDFHINT	(1 << 1)
#define SR_CRYPTOM_AES_ECB_256	1
#define SR_CRYPTOC_HMAC_SHA1	1

#define SR_CRYPTOKDFT_PKCS5_PBKDF2	1
#define SR_CRYPTOKDFT_KEYDISK		2
#define SR_CRYPTOKDFT_BCRYPT_PBKDF	3

#define DISKMAGIC		0x82564557U
#define FS_UNUSED		0
#define FS_SWAP			1
#define FS_BSDFFS		7
#define FS_RAID			19
#define MAXPARTITIONS		52
#define RAW_PART		2

#define PASS_MAX		1024

struct sr_metadata {
	uint64_t	ssd_magic;
	uint32_t	ssd_version;
	uint32_t	ssd_vol_flags;
	uint8_t		ssd_uuid[16];
	uint32_t	ssd_chunk_no;
	uint32_t	ssd_chunk_id;
	uint32_t	ssd_opt_no;
	uint32_t	ssd_secsize;
	uint32_t	ssd_volid;
	uint32_t	ssd_level;
	int64_t		ssd_size;
	char		ssd_vendor[8];
	char		ssd_product[16];
	char		ssd_revision[4];
	uint32_t	ssd_strip_size;
	/* end of the invariant part covered by ssd_checksum */
	uint8_t		ssd_checksum[16];
	char		ssd_devname[32];
	uint32_t	ssd_meta_flags;
	uint32_t	ssd_data_blkno;
	uint64_t	ssd_ondisk;
	int64_t		ssd_rebuild;
} __attribute__((packed));

#define SR_META_INVARIANT_SIZE	offsetof(struct sr_metadata, ssd_checksum)

struct sr_meta_chunk {
	uint32_t	scm_volid;
	uint32_t	scm_chunk_id;
	char		scm_devname[32];
	int64_t		scm_size;
	int64_t		scm_coerced_size;
	uint8_t		scm_uuid[16];
	uint8_t		scm_checksum[16];
	uint32_t	scm_status;
} __attribute__((packed));

struct sr_meta_opt_hdr {
	uint32_t	som_type;
	uint32_t	som_length;
	uint8_t		som_checksum[16];
} __attribute__((packed));

struct sr_crypto_pbkdf {
	uint32_t	len;
	uint32_t	type;
	uint32_t	rounds;
	uint8_t		salt[128];
} __attribute__((packed));

struct sr_meta_crypto {
	struct sr_meta_opt_hdr scm_hdr;
	uint32_t	scm_alg;
	uint32_t	scm_flags;
	uint32_t	scm_mask_alg;
	uint32_t	scm_pad1;
	uint8_t		scm_reserved[64];
	uint8_t		scm_key[SR_CRYPTO_MAXKEYS][SR_CRYPTO_KEYBYTES];
	uint8_t		scm_kdfhint[256];
	uint32_t	scm_check_alg;
	uint32_t	scm_pad2;
	uint8_t		scm_chk[64];	/* HMAC-SHA1 in the first 20 bytes */
} __attribute__((packed));

struct sr_meta_keydisk {
	struct sr_meta_opt_hdr skm_hdr;
	uint8_t		skm_maskkey[SR_CRYPTO_MASKBYTES];
} __attribute__((packed));

struct partition {
	uint32_t	p_size;
	uint32_t	p_offset;
	uint16_t	p_offseth;
	uint16_t	p_sizeh;
	uint8_t		p_fstype;
	uint8_t		p_fragblock;
	uint16_t	p_cpg;
} __attribute__((packed));

struct disklabel {
	uint32_t	d_magic;
	uint16_t	d_type;
	uint16_t	d_subtype;
	char		d_typename[16];
	char		d_packname[16];
	uint32_t	d_secsize;
	uint32_t	d_nsectors;
	uint32_t	d_ntracks;
	uint32_t	d_ncylinders;
	uint32_t	d_secpercyl;
	uint32_t	d_secperunit;
	uint8_t		d_uid[8];
	uint32_t	d_acylinders;
	uint16_t	d_bstarth;
	uint16_t	d_bendh;
	uint32_t	d_bstart;
	uint32_t	d_bend;
	uint32_t	d_flags;
	uint32_t	d_spare4[5];
	uint16_t	d_secperunith;
	uint16_t	d_version;
	uint32_t	d_spare[4];
	uint32_t	d_magic2;
	uint16_t	d_checksum;
	uint16_t	d_npartitions;
	uint32_t	d_spare2;
	uint32_t	d_spare3;
	struct partition d_partitions[MAXPARTITIONS];
} __attribute__((packed));

_Static_assert(sizeof(struct sr_metadata) == 168, "sr_metadata size");
_Static_assert(SR_META_INVARIANT_SIZE == 96, "sr_meta_invariant size");
_Static_assert(sizeof(struct sr_meta_chunk) == 92, "sr_meta_chunk size");
_Static_assert(sizeof(struct sr_meta_opt_hdr) == 24, "sr_meta_opt_hdr size");
_Static_assert(sizeof(struct sr_meta_crypto) == 2480, "sr_meta_crypto size");
_Static_assert(sizeof(struct sr_crypto_pbkdf) == 140, "sr_crypto_pbkdf size");
_Static_assert(offsetof(struct disklabel, d_partitions) == 148,
    "disklabel header size");
_Static_assert(sizeof(struct partition) == 16, "partition size");

/* One softraid chunk found on a device. */
struct chunk {
	uint64_t		off;	/* chunk start on the device, in blocks */
	char			part;	/* outer disklabel letter, or 0 */
	uint8_t			meta[SR_META_SIZE * DEV_BSIZE];
	struct sr_metadata	*sm;
	struct sr_meta_crypto	crypto;
	int			have_crypto;
	struct sr_meta_keydisk	keydisk;
	int			have_keydisk;
};

static int	fflag;		/* allow volumes larger than one key range */
static int	sflag;		/* read the passphrase from stdin */
static char	pflag;		/* outer partition letter to use */

static void
usage(void)
{
	fprintf(stderr,
	    "usage: srcrypt [-fs] [-k keydisk] [-p part] info device\n"
	    "       srcrypt [-fs] [-k keydisk] [-p part] open device name\n"
	    "       srcrypt [-fs] [-k keydisk] [-p part] table device\n"
	    "       srcrypt close name\n");
	exit(2);
}

static char
partletter(int i)
{
	return i < 26 ? 'a' + i : 'A' + (i - 26);
}

static void
preadall(int fd, void *buf, size_t len, uint64_t off)
{
	uint8_t	*p = buf;
	ssize_t	 n;

	while (len > 0) {
		n = pread(fd, p, len, off);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(1, "read at offset %" PRIu64, off);
		}
		if (n == 0)
			errx(1, "short read at offset %" PRIu64, off);
		p += n;
		off += n;
		len -= n;
	}
}

/* Return the device size in blocks. */
static uint64_t
devsize(int fd)
{
	struct stat	st;
	uint64_t	bytes;

	if (fstat(fd, &st) == -1)
		err(1, "fstat");
	if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &bytes) == -1)
			err(1, "BLKGETSIZE64");
	} else
		bytes = st.st_size;
	return bytes / DEV_BSIZE;
}

/*
 * Return the start of a partition block device on its parent disk, in
 * blocks. OpenBSD disklabel offsets are relative to the whole disk, so a
 * label read through a partition device must be shifted by this amount.
 */
static uint64_t
devstart(int fd)
{
	struct stat	 st;
	char		 path[128];
	FILE		*f;
	uint64_t	 start = 0;

	if (fstat(fd, &st) == -1 || !S_ISBLK(st.st_mode))
		return 0;
	snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/start",
	    major(st.st_rdev), minor(st.st_rdev));
	if ((f = fopen(path, "r")) == NULL)
		return 0;
	if (fscanf(f, "%" SCNu64, &start) != 1)
		start = 0;
	fclose(f);
	return start;
}

static uint16_t
dkcksum(const struct disklabel *lp)
{
	const uint16_t	*p = (const uint16_t *)lp;
	const uint16_t	*end;
	uint16_t	 sum = 0;

	end = (const uint16_t *)&lp->d_partitions[lp->d_npartitions];
	while (p < end)
		sum ^= *p++;
	return sum;
}

/* Read and check a disklabel at byte offset off. */
static int
readlabel(int fd, uint64_t off, uint64_t size, struct disklabel *lp)
{
	if (off + sizeof(*lp) > size * DEV_BSIZE)
		return -1;
	preadall(fd, lp, sizeof(*lp), off);
	if (lp->d_magic != DISKMAGIC || lp->d_magic2 != DISKMAGIC)
		return -1;
	if (lp->d_npartitions > MAXPARTITIONS || lp->d_secsize < DEV_BSIZE ||
	    lp->d_secsize % DEV_BSIZE != 0)
		return -1;
	if (dkcksum(lp) != 0)
		return -1;
	return 0;
}

/*
 * Find the OpenBSD disklabel on a disk, a disk image or an OpenBSD
 * partition. The label is 512 bytes into the OpenBSD area, for any sector
 * size. The area is the MBR partition of type 0xA6, the GPT partition of
 * type "OpenBSD data", or the device itself.
 */
static int
findlabel(int fd, uint64_t size, struct disklabel *lp)
{
	static const uint8_t gpt_obsd[16] = {	/* 824CC7A0-36A8-11E3-890A-952519AD3F61 */
		0xa0, 0xc7, 0x4c, 0x82, 0xa8, 0x36, 0xe3, 0x11,
		0x89, 0x0a, 0x95, 0x25, 0x19, 0xad, 0x3f, 0x61
	};
	uint8_t		 mbr[512], gpt[512], ent[128];
	uint64_t	 lba, start;
	uint32_t	 n, esize, i, j, k;
	uint32_t	 secsz[] = { 512, 4096 };

	if (readlabel(fd, DEV_BSIZE, size, lp) == 0)
		return 0;

	if (size < 2)
		return -1;
	preadall(fd, mbr, sizeof(mbr), 0);
	if (mbr[510] != 0x55 || mbr[511] != 0xaa)
		return -1;

	/* MBR sector numbers are in units of the unknown disk sector size. */
	for (i = 0; i < 4; i++) {
		uint8_t *p = mbr + 446 + 16 * i;
		uint32_t s;

		if (p[4] != 0xa6)
			continue;
		memcpy(&s, p + 8, 4);
		for (k = 0; k < 2; k++)
			if (readlabel(fd, (uint64_t)s * secsz[k] + DEV_BSIZE,
			    size, lp) == 0)
				return 0;
	}

	for (i = 0; i < 2; i++) {
		if ((uint64_t)secsz[i] * 2 > size * DEV_BSIZE)
			continue;
		preadall(fd, gpt, sizeof(gpt), secsz[i]);
		if (memcmp(gpt, "EFI PART", 8) != 0)
			continue;
		memcpy(&lba, gpt + 72, 8);
		memcpy(&n, gpt + 80, 4);
		memcpy(&esize, gpt + 84, 4);
		if (esize < 128 || esize > 4096 || n > 1024)
			continue;
		for (j = 0; j < n; j++) {
			uint64_t eoff = lba * secsz[i] + (uint64_t)j * esize;

			if (eoff + sizeof(ent) > size * DEV_BSIZE)
				break;
			preadall(fd, ent, sizeof(ent), eoff);
			if (memcmp(ent, gpt_obsd, 16) != 0)
				continue;
			memcpy(&start, ent + 32, 8);
			if (readlabel(fd, start * secsz[i] + DEV_BSIZE, size,
			    lp) == 0)
				return 0;
		}
	}
	return -1;
}

static uint64_t
dl_poffset(const struct disklabel *lp, const struct partition *pp)
{
	return (((uint64_t)pp->p_offseth << 32) + pp->p_offset) *
	    (lp->d_secsize / DEV_BSIZE);
}

static uint64_t
dl_psize(const struct disklabel *lp, const struct partition *pp)
{
	return (((uint64_t)pp->p_sizeh << 32) + pp->p_size) *
	    (lp->d_secsize / DEV_BSIZE);
}

static void
md5(const void *buf, size_t len, uint8_t out[16])
{
	unsigned int	n;

	if (!EVP_Digest(buf, len, out, &n, EVP_md5(), NULL))
		errx(1, "MD5 failed");
}

/*
 * Copy optional metadata item i into a buffer of its new-style size.
 * Old items have a fixed size, no length, and the payload at offset 8.
 */
static int
loadopt(struct chunk *c, uint8_t **pp, uint8_t *end, void *out,
    size_t outlen, uint32_t *type)
{
	struct sr_meta_opt_hdr	 hdr, *oh;
	uint8_t			 sum[16], *p = *pp;
	uint8_t			 buf[SR_META_SIZE * DEV_BSIZE];
	size_t			 len;

	(void)c;
	if (p + sizeof(hdr) > end)
		return -1;
	memcpy(&hdr, p, sizeof(hdr));
	*type = hdr.som_type;

	if (hdr.som_length == 0) {
		if (p + SR_OLD_META_OPT_SIZE > end)
			return -1;
		md5(p, SR_OLD_META_OPT_SIZE - 16, sum);
		if (memcmp(sum, p + SR_OLD_META_OPT_SIZE - 16, 16) != 0) {
			warnx("bad checksum on old optional metadata");
			return -1;
		}
		*pp = p + SR_OLD_META_OPT_SIZE;
		if (out == NULL)
			return 0;
		memset(out, 0, outlen);
		oh = out;
		oh->som_type = hdr.som_type;
		oh->som_length = outlen;
		memcpy((uint8_t *)out + sizeof(hdr), p + SR_OLD_META_OPT_OFFSET,
		    outlen - sizeof(hdr));
		return 0;
	}

	len = hdr.som_length;
	if (len < sizeof(hdr) || p + len > end)
		return -1;
	memcpy(buf, p, len);
	memset(((struct sr_meta_opt_hdr *)buf)->som_checksum, 0, 16);
	md5(buf, len, sum);
	explicit_bzero(buf, len);
	if (memcmp(sum, hdr.som_checksum, 16) != 0) {
		warnx("bad checksum on optional metadata type %u", hdr.som_type);
		return -1;
	}
	*pp = p + len;
	if (out == NULL)
		return 0;
	if (len < outlen) {
		warnx("optional metadata type %u too short", hdr.som_type);
		return -1;
	}
	memcpy(out, p, outlen);
	return 0;
}

/* Read and check softraid metadata at chunk offset off. */
static int
readchunk(int fd, uint64_t size, uint64_t off, struct chunk *c)
{
	struct sr_metadata	*sm;
	uint8_t			 sum[16], *p, *end;
	uint32_t		 i, type;

	memset(c, 0, sizeof(*c));
	if (off + SR_META_OFFSET + SR_META_SIZE > size)
		return -1;
	preadall(fd, c->meta, sizeof(c->meta),
	    (off + SR_META_OFFSET) * DEV_BSIZE);
	c->off = off;
	c->sm = sm = (struct sr_metadata *)c->meta;

	if (sm->ssd_magic != SR_MAGIC)
		return -1;
	if (sm->ssd_version < 3 || sm->ssd_version > 6) {
		warnx("unsupported metadata version %u", sm->ssd_version);
		return -1;
	}
	md5(sm, SR_META_INVARIANT_SIZE, sum);
	if (memcmp(sum, sm->ssd_checksum, 16) != 0) {
		warnx("bad metadata checksum");
		return -1;
	}
	if (sm->ssd_chunk_no == 0 || sm->ssd_chunk_no > 64) {
		warnx("bad chunk count %u", sm->ssd_chunk_no);
		return -1;
	}

	if (sm->ssd_version <= 5)
		sm->ssd_secsize = DEV_BSIZE;
	if (sm->ssd_data_blkno == 0)
		sm->ssd_data_blkno = sm->ssd_version == 3 ?
		    SR_META_V3_DATA_OFFSET : SR_DATA_OFFSET;

	end = c->meta + sizeof(c->meta);
	p = c->meta + sizeof(*sm) + sm->ssd_chunk_no * sizeof(struct sr_meta_chunk);
	for (i = 0; i < sm->ssd_opt_no; i++) {
		uint8_t		 hdr[sizeof(struct sr_meta_opt_hdr)];
		uint8_t		*q = p;

		if (p + sizeof(hdr) > end)
			return -1;
		memcpy(&type, p, 4);
		switch (type) {
		case SR_OPT_CRYPTO:
			if (loadopt(c, &p, end, &c->crypto, sizeof(c->crypto),
			    &type) == -1)
				return -1;
			c->have_crypto = 1;
			break;
		case SR_OPT_KEYDISK:
			if (loadopt(c, &p, end, &c->keydisk,
			    sizeof(c->keydisk), &type) == -1)
				return -1;
			c->have_keydisk = 1;
			break;
		default:
			if (loadopt(c, &p, end, NULL, 0, &type) == -1)
				return -1;
			break;
		}
		if (p <= q)
			return -1;
	}
	return 0;
}

/*
 * Find a softraid chunk of the given level on a device. The device may be
 * the chunk itself, an OpenBSD partition, a whole disk, or a disk image.
 */
static int
findchunk(int fd, uint32_t level, struct chunk *c)
{
	struct disklabel	 dl;
	uint64_t		 size, base, off;
	int			 i;

	size = devsize(fd);
	if (readchunk(fd, size, 0, c) == 0 && c->sm->ssd_level == level)
		return 0;

	if (findlabel(fd, size, &dl) == -1)
		return -1;

	base = devstart(fd);
	for (i = 0; i < dl.d_npartitions; i++) {
		struct partition *pp = &dl.d_partitions[i];

		if (pp->p_fstype != FS_RAID || dl_psize(&dl, pp) == 0)
			continue;
		if (pflag && partletter(i) != pflag)
			continue;
		off = dl_poffset(&dl, pp);
		if (off < base)
			continue;
		off -= base;
		if (readchunk(fd, size, off, c) == 0 &&
		    c->sm->ssd_level == level) {
			c->part = partletter(i);
			return 0;
		}
	}
	return -1;
}

static int
opendev(const char *path)
{
	int	fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		err(1, "%s", path);
	return fd;
}

static const char *
kdfname(uint32_t type)
{
	switch (type) {
	case SR_CRYPTOKDFT_PKCS5_PBKDF2:
		return "pkcs5_pbkdf2";
	case SR_CRYPTOKDFT_KEYDISK:
		return "keydisk";
	case SR_CRYPTOKDFT_BCRYPT_PBKDF:
		return "bcrypt_pbkdf";
	}
	return "unknown";
}

static uint32_t
numkeys(const struct sr_metadata *sm)
{
	return ((sm->ssd_size - 1) >> SR_CRYPTO_KEY_BLKSHIFT) + 1;
}

/* Check the parts of the crypto metadata that unlock depends on. */
static void
checkcrypto(const struct chunk *c, int fd)
{
	const struct sr_metadata	*sm = c->sm;
	const struct sr_meta_crypto	*cm = &c->crypto;
	uint64_t			 end, size;

	if (!c->have_crypto)
		errx(1, "volume has no crypto metadata");
	if (!(cm->scm_flags & SR_CRYPTOF_KEY))
		errx(1, "volume has no disk keys");
	if (cm->scm_alg != SR_CRYPTOA_AES_XTS_128 &&
	    cm->scm_alg != SR_CRYPTOA_AES_XTS_256)
		errx(1, "unknown crypto algorithm %u", cm->scm_alg);
	if (cm->scm_mask_alg != SR_CRYPTOM_AES_ECB_256)
		errx(1, "unknown mask algorithm %u", cm->scm_mask_alg);
	if (cm->scm_check_alg != SR_CRYPTOC_HMAC_SHA1)
		errx(1, "unknown check algorithm %u", cm->scm_check_alg);
	if (sm->ssd_size <= 0 || numkeys(sm) > SR_CRYPTO_MAXKEYS)
		errx(1, "bad volume size %" PRId64, sm->ssd_size);
	end = c->off + sm->ssd_data_blkno + (uint64_t)sm->ssd_size;
	size = devsize(fd);
	if (end > size) {
		/* A disklabel partition can extend past its MBR or GPT partition. */
		warnx("volume ends at block %" PRIu64 ", past the end of "
		    "the device (%" PRIu64 " blocks)", end, size);
		if (devstart(fd) > 0)
			errx(1, "device is a partition; try the whole disk");
		exit(1);
	}
}

static void
printuuid(const uint8_t *u)
{
	int	i;

	for (i = 0; i < 16; i++)
		printf("%02x%s", u[i], (i == 3 || i == 5 || i == 7 ||
		    i == 9) ? "-" : "");
}

static void
info(const struct chunk *c)
{
	const struct sr_metadata	*sm = c->sm;
	const struct sr_meta_chunk	*mc;
	const struct sr_meta_crypto	*cm = &c->crypto;
	struct sr_crypto_pbkdf		 kdf;

	mc = (const struct sr_meta_chunk *)(sm + 1);
	printf("version     %u\n", sm->ssd_version);
	printf("uuid        ");
	printuuid(sm->ssd_uuid);
	printf("\n");
	if (sm->ssd_level == SR_KEYDISK_LEVEL)
		printf("level       keydisk\n");
	else
		printf("level       %c\n", isprint(sm->ssd_level) ?
		    sm->ssd_level : '?');
	printf("devname     %.32s\n", sm->ssd_devname);
	printf("chunk       %.32s", mc->scm_devname);
	if (c->part)
		printf(" (partition %c)", c->part);
	printf(" at block %" PRIu64 "\n", c->off);
	printf("data        block %u\n", sm->ssd_data_blkno);
	printf("size        %" PRId64 " blocks (%.1f GiB)\n", sm->ssd_size,
	    sm->ssd_size / 2097152.0);
	printf("secsize     %u\n", sm->ssd_secsize);
	printf("ondisk      %" PRIu64 "\n", sm->ssd_ondisk);
	if (sm->ssd_level == SR_KEYDISK_LEVEL) {
		printf("mask key    %s\n", c->have_keydisk ? "present" :
		    "missing");
		return;
	}
	if (!c->have_crypto)
		return;
	printf("cipher      %s\n", cm->scm_alg == SR_CRYPTOA_AES_XTS_256 ?
	    "aes-xts-256" : cm->scm_alg == SR_CRYPTOA_AES_XTS_128 ?
	    "aes-xts-128" : "unknown");
	if (cm->scm_flags & SR_CRYPTOF_KDFHINT) {
		memcpy(&kdf, cm->scm_kdfhint, sizeof(kdf));
		printf("kdf         %s", kdfname(kdf.type));
		if (kdf.type != SR_CRYPTOKDFT_KEYDISK)
			printf(", %u rounds", kdf.rounds);
		printf("\n");
	} else
		printf("kdf         none\n");
	if (sm->ssd_size > 0) {
		printf("keys        %u\n", numkeys(sm));
		if (numkeys(sm) > 1)
			printf("warning     volume is larger than 512 GiB; "
			    "data near key boundaries can be wrong\n");
	}
}

/* Read a passphrase like bioctl: strip one trailing newline. */
static size_t
readpass(char *buf, size_t len)
{
	struct termios	 t, saved;
	int		 fd, tty = 0, c;
	size_t		 n = 0;
	FILE		*f;

	if (sflag)
		fd = dup(STDIN_FILENO);
	else if ((fd = open("/dev/tty", O_RDWR | O_CLOEXEC)) == -1)
		err(1, "/dev/tty");
	if (fd == -1)
		err(1, "dup");
	if (!sflag && tcgetattr(fd, &saved) == 0) {
		tty = 1;
		t = saved;
		t.c_lflag &= ~(ECHO | ECHONL);
		t.c_lflag |= ICANON;
		tcsetattr(fd, TCSAFLUSH, &t);
		(void)!write(fd, "Passphrase: ", 12);
	}
	if ((f = fdopen(fd, "r")) == NULL)
		err(1, "fdopen");
	setvbuf(f, NULL, _IONBF, 0);
	while ((c = fgetc(f)) != EOF && c != '\n') {
		if (n + 1 >= len)
			errx(1, "passphrase too long");
		buf[n++] = c;
	}
	buf[n] = '\0';
	if (tty) {
		tcsetattr(fd, TCSAFLUSH, &saved);
		(void)!write(fd, "\n", 1);
	}
	fclose(f);
	if (n == 0)
		errx(1, "invalid passphrase length");
	return n;
}

static void
derivemask(const struct chunk *c, const char *keydisk, uint8_t *mask)
{
	struct sr_crypto_pbkdf	 kdf;
	struct chunk		*kc;
	char			*pass;
	size_t			 plen;
	int			 fd;

	if (keydisk != NULL) {
		if ((kc = malloc(sizeof(*kc))) == NULL)
			err(1, NULL);
		fd = opendev(keydisk);
		if (findchunk(fd, SR_KEYDISK_LEVEL, kc) == -1)
			errx(1, "%s: no softraid keydisk chunk found", keydisk);
		close(fd);
		if (!kc->have_keydisk)
			errx(1, "%s: keydisk has no mask key", keydisk);
		if (memcmp(kc->sm->ssd_uuid, c->sm->ssd_uuid, 16) != 0)
			warnx("keydisk uuid does not match the volume");
		memcpy(mask, kc->keydisk.skm_maskkey, SR_CRYPTO_MASKBYTES);
		explicit_bzero(kc, sizeof(*kc));
		free(kc);
		return;
	}

	if (!(c->crypto.scm_flags & SR_CRYPTOF_KDFHINT))
		errx(1, "volume has no KDF hint; use -k keydisk");
	memcpy(&kdf, c->crypto.scm_kdfhint, sizeof(kdf));
	if (kdf.type == SR_CRYPTOKDFT_KEYDISK)
		errx(1, "volume uses a keydisk; use -k keydisk");
	if (kdf.len != sizeof(kdf))
		errx(1, "KDF hint has invalid size");
	if (kdf.type != SR_CRYPTOKDFT_PKCS5_PBKDF2 &&
	    kdf.type != SR_CRYPTOKDFT_BCRYPT_PBKDF)
		errx(1, "unknown KDF type %u", kdf.type);
	if (kdf.rounds == 0 || kdf.rounds > INT_MAX)
		errx(1, "bad KDF rounds %u", kdf.rounds);

	if ((pass = malloc(PASS_MAX)) == NULL)
		err(1, NULL);
	plen = readpass(pass, PASS_MAX);
	if (kdf.type == SR_CRYPTOKDFT_PKCS5_PBKDF2) {
		if (!PKCS5_PBKDF2_HMAC_SHA1(pass, plen, kdf.salt,
		    sizeof(kdf.salt), kdf.rounds, SR_CRYPTO_MASKBYTES, mask))
			errx(1, "pkcs5_pbkdf2 failed");
	} else {
		if (bcrypt_pbkdf(pass, plen, kdf.salt, sizeof(kdf.salt),
		    mask, SR_CRYPTO_MASKBYTES, kdf.rounds) != 0)
			errx(1, "bcrypt_pbkdf failed");
	}
	explicit_bzero(pass, PASS_MAX);
	free(pass);
}

/* Unwrap the disk keys with the mask key and check the HMAC. */
static void
unwrap(const struct chunk *c, const uint8_t *mask, uint8_t *keys)
{
	const struct sr_meta_crypto	*cm = &c->crypto;
	EVP_CIPHER_CTX			*ctx;
	uint8_t				 ck[SHA_DIGEST_LENGTH];
	uint8_t				 mac[EVP_MAX_MD_SIZE];
	unsigned int			 maclen;
	int				 n, fin;

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		errx(1, "EVP_CIPHER_CTX_new failed");
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, mask, NULL) ||
	    !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
	    !EVP_DecryptUpdate(ctx, keys, &n, (const uint8_t *)cm->scm_key,
	    sizeof(cm->scm_key)) ||
	    !EVP_DecryptFinal_ex(ctx, keys + n, &fin))
		errx(1, "key unwrap failed");
	EVP_CIPHER_CTX_free(ctx);

	SHA1(mask, SR_CRYPTO_MASKBYTES, ck);
	if (HMAC(EVP_sha1(), ck, sizeof(ck), keys, sizeof(cm->scm_key), mac,
	    &maclen) == NULL)
		errx(1, "HMAC failed");
	explicit_bzero(ck, sizeof(ck));
	if (maclen != 20 || CRYPTO_memcmp(mac, cm->scm_chk, 20) != 0) {
		explicit_bzero(keys, sizeof(cm->scm_key));
		errx(1, "incorrect key or passphrase");
	}
}

/*
 * Build dm-crypt target lines. Key i covers volume blocks [i << 30,
 * (i + 1) << 30). The IV is the absolute volume block number, so
 * iv_offset equals the target start.
 */
static void
buildtable(const struct chunk *c, const uint8_t *keys, const char *dev,
    void (*emit)(void *, uint64_t, uint64_t, const char *), void *arg)
{
	const struct sr_metadata	*sm = c->sm;
	char				 params[512];
	char				 hex[SR_CRYPTO_KEYBYTES * 2 + 1];
	uint64_t			 start, len, total = sm->ssd_size;
	size_t				 klen, j;
	uint32_t			 i;

	klen = c->crypto.scm_alg == SR_CRYPTOA_AES_XTS_256 ? 64 : 32;
	for (i = 0; i < numkeys(sm); i++) {
		start = (uint64_t)i << SR_CRYPTO_KEY_BLKSHIFT;
		len = total - start;
		if (len > (1ULL << SR_CRYPTO_KEY_BLKSHIFT))
			len = 1ULL << SR_CRYPTO_KEY_BLKSHIFT;
		for (j = 0; j < klen; j++)
			snprintf(hex + 2 * j, 3, "%02x",
			    keys[i * SR_CRYPTO_KEYBYTES + j]);
		snprintf(params, sizeof(params),
		    "aes-xts-plain64 %s %" PRIu64 " %s %" PRIu64,
		    hex, start, dev, c->off + sm->ssd_data_blkno + start);
		emit(arg, start, len, params);
		explicit_bzero(hex, sizeof(hex));
		explicit_bzero(params, sizeof(params));
	}
}

static void
emitprint(void *arg, uint64_t start, uint64_t len, const char *params)
{
	(void)arg;
	printf("%" PRIu64 " %" PRIu64 " crypt %s\n", start, len, params);
}

static void
emitdm(void *arg, uint64_t start, uint64_t len, const char *params)
{
	if (!dm_task_add_target(arg, start, len, "crypt", params))
		errx(1, "dm_task_add_target failed");
}

static int
dmcreate(const char *name, struct dm_task *dmt)
{
	uint32_t	cookie = 0;
	int		ok;

	if (!dm_task_set_name(dmt, name) || !dm_task_set_ro(dmt) ||
	    !dm_task_set_cookie(dmt, &cookie, 0))
		errx(1, "%s: dm task setup failed", name);
	ok = dm_task_run(dmt);
	dm_udev_wait(cookie);
	return ok ? 0 : -1;
}

static int
dmremove(const char *name)
{
	struct dm_task	*dmt;
	uint32_t	 cookie = 0;
	int		 ok;

	if ((dmt = dm_task_create(DM_DEVICE_REMOVE)) == NULL)
		errx(1, "dm_task_create failed");
	if (!dm_task_set_name(dmt, name) ||
	    !dm_task_set_cookie(dmt, &cookie, 0))
		errx(1, "%s: dm task setup failed", name);
	dm_task_retry_remove(dmt);
	ok = dm_task_run(dmt);
	dm_udev_wait(cookie);
	dm_task_destroy(dmt);
	return ok ? 0 : -1;
}

/*
 * Return the Linux ufstype for the FFS file system at block off, or NULL.
 * The Linux UFS driver cannot mount a fragment size over 4096.
 */
static const char *
ffstype(int fd, uint64_t off, uint64_t len, int32_t *fsize)
{
	static const struct {
		uint32_t	 sblock;
		int32_t		 magic;
		const char	*type;
	} sb[] = {
		{ 65536, 0x19540119, "ufs2" },
		{ 8192, 0x011954, "44bsd" },
	};
	uint8_t	buf[1376];
	int32_t	magic;
	size_t	i;

	for (i = 0; i < 2; i++) {
		if (sb[i].sblock + sizeof(buf) > len * DEV_BSIZE)
			continue;
		preadall(fd, buf, sizeof(buf), off * DEV_BSIZE + sb[i].sblock);
		memcpy(&magic, buf + 1372, 4);
		if (magic != sb[i].magic)
			continue;
		memcpy(fsize, buf + 52, 4);
		return sb[i].type;
	}
	return NULL;
}

/* Create one read-only dm-linear device per partition of the inner label. */
static void
mkparts(const char *name)
{
	struct disklabel	 dl;
	struct dm_task		*dmt;
	char			 path[PATH_MAX], pname[128], params[PATH_MAX + 32];
	uint64_t		 size, off, len;
	int			 fd, i;

	snprintf(path, sizeof(path), "%s/%s", dm_dir(), name);
	fd = opendev(path);
	size = devsize(fd);
	if (findlabel(fd, size, &dl) == -1) {
		warnx("%s: no disklabel inside the volume", path);
		close(fd);
		return;
	}

	for (i = 0; i < dl.d_npartitions; i++) {
		struct partition *pp = &dl.d_partitions[i];
		const char *type = NULL;
		int32_t fsize = 0;

		if (i == RAW_PART || pp->p_fstype == FS_UNUSED)
			continue;
		off = dl_poffset(&dl, pp);
		len = dl_psize(&dl, pp);
		if (len == 0)
			continue;
		if (off + len > size) {
			warnx("partition %c extends past the volume",
			    partletter(i));
			continue;
		}
		snprintf(pname, sizeof(pname), "%s-%c", name, partletter(i));
		snprintf(params, sizeof(params), "%s %" PRIu64, path, off);
		if ((dmt = dm_task_create(DM_DEVICE_CREATE)) == NULL)
			errx(1, "dm_task_create failed");
		if (!dm_task_add_target(dmt, 0, len, "linear", params))
			errx(1, "dm_task_add_target failed");
		if (dmcreate(pname, dmt) == -1) {
			warnx("%s: create failed", pname);
			dm_task_destroy(dmt);
			continue;
		}
		dm_task_destroy(dmt);
		if (pp->p_fstype == FS_BSDFFS)
			type = ffstype(fd, off, len, &fsize);
		if (type == NULL)
			printf("%s/%s\n", dm_dir(), pname);
		else if (fsize > 4096)
			printf("%s/%s ufstype=%s (fsize %d: Linux UFS "
			    "cannot mount it)\n", dm_dir(), pname, type, fsize);
		else
			printf("%s/%s ufstype=%s\n", dm_dir(), pname, type);
	}
	close(fd);
}

static void
cmdopen(const struct chunk *c, int fd, const char *dev, const char *name,
    const uint8_t *keys)
{
	struct dm_task	*dmt;
	struct stat	 st;
	char		 devnum[32];

	if (fstat(fd, &st) == -1)
		err(1, "fstat");
	if (!S_ISBLK(st.st_mode))
		errx(1, "%s: not a block device; use losetup -r first", dev);
	snprintf(devnum, sizeof(devnum), "%u:%u", major(st.st_rdev),
	    minor(st.st_rdev));

	if ((dmt = dm_task_create(DM_DEVICE_CREATE)) == NULL)
		errx(1, "dm_task_create failed");
	dm_task_secure_data(dmt);
	buildtable(c, keys, devnum, emitdm, dmt);
	if (dmcreate(name, dmt) == -1)
		errx(1, "%s: create failed", name);
	dm_task_destroy(dmt);
	printf("%s/%s\n", dm_dir(), name);
	mkparts(name);
}

static void
cmdclose(const char *name)
{
	struct dm_task		*dmt;
	struct dm_names		*n;
	size_t			 len = strlen(name);
	unsigned int		 next;
	int			 rv = 0;

	if ((dmt = dm_task_create(DM_DEVICE_LIST)) == NULL ||
	    !dm_task_run(dmt))
		errx(1, "cannot list device-mapper devices");
	n = dm_task_get_names(dmt);
	if (n != NULL && n->dev != 0) {
		do {
			if (strncmp(n->name, name, len) == 0 &&
			    n->name[len] == '-' && isalpha(n->name[len + 1]) &&
			    n->name[len + 2] == '\0' && dmremove(n->name) == -1) {
				warnx("%s: remove failed", n->name);
				rv = 1;
			}
			next = n->next;
			n = (struct dm_names *)((char *)n + next);
		} while (next != 0);
	}
	dm_task_destroy(dmt);
	if (dmremove(name) == -1)
		errx(1, "%s: remove failed", name);
	exit(rv);
}

int
main(int argc, char *argv[])
{
	struct chunk	*c;
	const char	*keydisk = NULL, *cmd, *dev;
	uint8_t		*mask, *keys;
	size_t		 lockedlen;
	int		 ch, fd;

	while ((ch = getopt(argc, argv, "fk:p:s")) != -1) {
		switch (ch) {
		case 'f':
			fflag = 1;
			break;
		case 'k':
			keydisk = optarg;
			break;
		case 'p':
			if (strlen(optarg) != 1 || !isalpha((unsigned char)*optarg))
				usage();
			pflag = *optarg;
			break;
		case 's':
			sflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2)
		usage();
	cmd = argv[0];

	if (strcmp(cmd, "close") == 0) {
		if (argc != 2)
			usage();
		cmdclose(argv[1]);
	}
	if (strcmp(cmd, "info") != 0 && strcmp(cmd, "table") != 0 &&
	    strcmp(cmd, "open") != 0)
		usage();
	if ((strcmp(cmd, "open") == 0) != (argc == 3) || argc > 3)
		usage();
	dev = argv[1];

	if ((c = malloc(sizeof(*c))) == NULL)
		err(1, NULL);
	fd = opendev(dev);
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (strcmp(cmd, "info") == 0) {
		if (findchunk(fd, SR_CRYPTO_LEVEL, c) == -1 &&
		    findchunk(fd, SR_KEYDISK_LEVEL, c) == -1)
			errx(1, "%s: no softraid CRYPTO or keydisk chunk", dev);
		info(c);
		return 0;
	}
	if (findchunk(fd, SR_CRYPTO_LEVEL, c) == -1)
		errx(1, "%s: no softraid CRYPTO chunk found", dev);

	checkcrypto(c, fd);
	if (numkeys(c->sm) > 1 && !fflag)
		errx(1, "volume is larger than 512 GiB; data near key "
		    "boundaries can be wrong; use -f to continue");

	/* Keep key material out of swap. */
	lockedlen = SR_CRYPTO_MASKBYTES + sizeof(c->crypto.scm_key);
	if ((mask = mmap(NULL, lockedlen, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
		err(1, "mmap");
	if (mlock(mask, lockedlen) == -1)
		warn("mlock");
	madvise(mask, lockedlen, MADV_DONTDUMP);
	keys = mask + SR_CRYPTO_MASKBYTES;

	derivemask(c, keydisk, mask);
	unwrap(c, mask, keys);
	explicit_bzero(mask, SR_CRYPTO_MASKBYTES);

	if (strcmp(cmd, "table") == 0) {
		char devnum[32];
		struct stat st;

		if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
			snprintf(devnum, sizeof(devnum), "%u:%u",
			    major(st.st_rdev), minor(st.st_rdev));
			dev = devnum;
		}
		buildtable(c, keys, dev, emitprint, NULL);
		fflush(stdout);
	} else
		cmdopen(c, fd, dev, argv[2], keys);

	explicit_bzero(keys, sizeof(c->crypto.scm_key));
	explicit_bzero(c, sizeof(*c));
	munmap(mask, lockedlen);
	close(fd);
	return 0;
}
