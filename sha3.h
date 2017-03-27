/*
 * Common values for SHA-3 algorithms
 */
#ifndef __SHA3_H__
#define __SHA3_H__
#include <stdint.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)

#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)

#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)

#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3_ctx {
	uint64_t	st[25];
	unsigned int	md_len;
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	unsigned char	buf[SHA3_224_BLOCK_SIZE];
};

int sha3_init(struct sha3_ctx *ctx, unsigned int digest_sz);
int sha3_update(struct sha3_ctx *ctx, const void *data,
		       unsigned int len);
int sha3_final(struct sha3_ctx *ctx, void *out, unsigned int outlen);

#endif
