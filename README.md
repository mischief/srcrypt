# srcrypt

Open OpenBSD softraid CRYPTO volumes (`bioctl -c C`) on Linux, read-only.

srcrypt reads the softraid metadata, derives the mask key with
bcrypt_pbkdf or PBKDF2 (or reads it from a keydisk), unwraps the disk keys,
and loads a dm-crypt `aes-xts-plain64` table. The kernel decrypts the data.
Each partition of the inner disklabel gets a read-only dm-linear device.
srcrypt exits after `open`; it is not in the I/O path.

## Build

Needs a C compiler, make, pkg-config, OpenSSL 3 (libcrypto) and
libdevmapper (lvm2). `bcrypt_pbkdf.c`, `blowfish.c` and `blf.h` come from
OpenBSD.

    make

At run time the kernel needs `dm_crypt`, and `ufs` to mount the result.

## Use

    srcrypt [-fs] [-k keydisk] [-p part] info device
    srcrypt [-fs] [-k keydisk] [-p part] open device name
    srcrypt [-fs] [-k keydisk] [-p part] table device
    srcrypt close name

Example:

    srcrypt info /dev/nvme1n1p2
    sudo srcrypt open /dev/nvme1n1p2 obsd     # asks for the passphrase
    sudo mount -t ufs -o ro,ufstype=ufs2 /dev/mapper/obsd-a /mnt
    ...
    sudo umount /mnt
    sudo srcrypt close obsd

`open` creates `/dev/mapper/NAME` for the whole volume and `NAME-a`,
`NAME-d`, ... for its partitions, and prints the `ufstype` for each
FFS partition. `close` removes all of them.

The device can be the RAID partition itself, the OpenBSD MBR or GPT
partition, or the whole disk. `info` and `table` also take a disk image.
`open` needs a block device, so attach an image first:

    sudo losetup -r -f --show disk.img

Options:

- `-k dev`: read the mask key from a keydisk instead of a passphrase.
- `-p x`: use RAID partition `x` of the outer disklabel.
- `-s`: read the passphrase from stdin instead of the terminal.
- `-f`: allow volumes larger than 512 GiB (see below).

`info` also works on a keydisk. `table` prints the dm-crypt table with the
disk key in it; do not leave it in logs.

Use `ufstype=ufs2` for FFS2 (the default on new installs) and
`ufstype=44bsd` for FFS1.

The Linux UFS driver cannot mount a file system with a fragment size
over 4096 bytes. OpenBSD `disklabel` gives partitions over 512 GiB a
fragment size of 8192, so Linux cannot mount them; `open` says so.
Partitions up to 512 GiB use 2048 or 4096 and mount.

On a disk with 4096-byte sectors the dm devices also have 4096-byte
sectors, and the Linux UFS driver cannot mount them ("failed to set
blocksize"). Put a 512-byte loop device on top:

    sudo losetup -r -b 512 -f --show /dev/mapper/obsd-a
    sudo mount -t ufs -o ro,ufstype=ufs2 /dev/loopN /mnt

## Limits

- Mount read-only. Linux UFS write support is experimental and can damage
  the file system. srcrypt makes every device read-only.
- OpenBSD uses a new disk key for each 512 GiB of the volume. It picks the
  key from the first block of an I/O, so an I/O that crosses a 512 GiB
  boundary uses the previous key for the blocks after the boundary.
  srcrypt always uses the correct key for each block. This matches
  OpenBSD reads that do not cross a boundary, but data that OpenBSD wrote
  with a crossing I/O reads back wrong. At most 63.5 KiB after each
  boundary is affected. srcrypt refuses such volumes unless you give `-f`.
- PBKDF2 volumes (made before OpenBSD 6.1) and metadata older than
  version 6 have code paths but are not tested.
- Keydisks in the original format, with the key in the crypto metadata,
  are not supported.
- Little-endian hosts only; softraid metadata is in host byte order.

## Tests

Tested against volumes made by OpenBSD 8.0 `bioctl`. Each test compares
SHA-256 hashes of data read on Linux with the same data read on OpenBSD.

- Passphrase (bcrypt_pbkdf), GPT outer disk, MBR inner disk: FFS2
  files match.
- Keydisk: raw data matches.
- 520 GiB volume (2 disk keys): raw data in both key ranges matches.
- 5 TiB volume (10 disk keys): raw data in all 10 key ranges matches.
  A 200 GiB FFS2 partition that crosses a key boundary mounts and its
  files match.
- Partition that starts above sector 2^32: the dm-linear device is at the
  correct offset. Not mounted, because the partition is over 512 GiB.
- Disk with 4096-byte sectors, GPT: raw data matches, and FFS2 files
  match through a 512-byte loop device.
