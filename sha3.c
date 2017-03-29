#include <stdint.h>
#include <string.h>
#include "sha3.h"

#define KECCAK_ROUNDS 24

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
	1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
	27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
	10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

#ifdef KECCAKF_MACRO

#define TIT(st, bc)                                               \
	do {                                                      \
		bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20]; \
		bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21]; \
		bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22]; \
		bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23]; \
		bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24]; \
	} while (0)

#define TST(st, i, t)                                             \
	do {                                                      \
		st[0 + i] ^= t;                                   \
		st[5 + i] ^= t;                                   \
		st[10 + i] ^= t;                                  \
		st[15 + i] ^= t;                                  \
		st[20 + i] ^= t;                                  \
	} while (0)

#define TBC(st, bc)                                               \
	do {                                                      \
		TST(st, 0, (bc[4] ^ ROTL64(bc[1], 1)));           \
		TST(st, 1, (bc[0] ^ ROTL64(bc[2], 1)));           \
		TST(st, 2, (bc[1] ^ ROTL64(bc[3], 1)));           \
		TST(st, 3, (bc[2] ^ ROTL64(bc[4], 1)));           \
		TST(st, 4, (bc[3] ^ ROTL64(bc[0], 1)));           \
	} while (0)

#define RP(st, bc)                                                \
	do {                                                      \
		int j;                                            \
		uint64_t t = st[1];                               \
		j = keccakf_piln[0]; bc[0] = st[j];               \
                st[j] = ROTL64(t, keccakf_rotc[0]); t = bc[0];    \
		j = keccakf_piln[1]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[1]); t = bc[0];    \
		j = keccakf_piln[2]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[2]); t = bc[0];    \
		j = keccakf_piln[3]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[3]); t = bc[0];    \
		j = keccakf_piln[4]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[4]); t = bc[0];    \
		j = keccakf_piln[5]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[5]); t = bc[0];    \
		j = keccakf_piln[6]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[6]); t = bc[0];    \
		j = keccakf_piln[7]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[7]); t = bc[0];    \
		j = keccakf_piln[8]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[8]); t = bc[0];    \
		j = keccakf_piln[9]; bc[0] = st[j];               \
		st[j] = ROTL64(t, keccakf_rotc[9]); t = bc[0];    \
		j = keccakf_piln[10]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[10]); t = bc[0];   \
		j = keccakf_piln[11]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[11]); t = bc[0];   \
		j = keccakf_piln[12]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[12]); t = bc[0];   \
		j = keccakf_piln[13]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[13]); t = bc[0];   \
		j = keccakf_piln[14]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[14]); t = bc[0];   \
		j = keccakf_piln[15]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[15]); t = bc[0];   \
		j = keccakf_piln[16]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[16]); t = bc[0];   \
		j = keccakf_piln[17]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[17]); t = bc[0];   \
		j = keccakf_piln[18]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[18]); t = bc[0];   \
		j = keccakf_piln[19]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[19]); t = bc[0];   \
		j = keccakf_piln[20]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[20]); t = bc[0];   \
		j = keccakf_piln[21]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[21]); t = bc[0];   \
		j = keccakf_piln[22]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[22]); t = bc[0];   \
		j = keccakf_piln[23]; bc[0] = st[j];              \
		st[j] = ROTL64(t, keccakf_rotc[23]); t = bc[0];   \
	} while (0)

#define CBC(st, bc, j)                                            \
	do {                                                      \
		bc[0] = st[j];                                    \
		bc[1] = st[j + 1];                                \
		bc[2] = st[j + 2];                                \
		bc[3] = st[j + 3];                                \
		bc[4] = st[j + 4];                                \
	} while (0)

#define CBCST(st, bc, j)                                          \
	do {                                                      \
		st[j] ^= (~bc[1]) & bc[2];                        \
		st[j + 1] ^= (~bc[2]) & bc[3];                    \
		st[j + 2] ^= (~bc[3]) & bc[4];                    \
		st[j + 3] ^= (~bc[4]) & bc[0];                    \
		st[j + 4] ^= (~bc[0]) & bc[1];                    \
	} while (0)

#define CHI(st, bc)                 \
	do {                        \
		CBC(st, bc, 0);     \
		CBCST(st, bc, 0);   \
		CBC(st, bc, 5);     \
		CBCST(st, bc, 5);   \
		CBC(st, bc, 10);     \
		CBCST(st, bc, 10);   \
		CBC(st, bc, 15);     \
		CBCST(st, bc, 15);   \
		CBC(st, bc, 20);     \
		CBCST(st, bc, 20);   \
	} while (0)
	
static void keccakf(uint64_t st[25])
{
	int round;
	uint64_t bc[5];

	for (round = 0; round < KECCAK_ROUNDS; round++) {

		/* Theta */
		TIT(st, bc);
		TBC(st, bc);

		/* Rho Pi */
		RP(st, bc);

		/* Chi */
		CHI(st, bc);

		/* Iota */
		st[0] ^= keccakf_rndc[round];
	}
}

#else //KECCAKF_MACRO

/* update the state with given number of rounds */
static void keccakf(uint64_t st[25])
{
	int i, j, round;
	uint64_t t, bc[5];

	for (round = 0; round < KECCAK_ROUNDS; round++) {

		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15]
				^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		/* Rho Pi */
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) &
					     bc[(i + 2) % 5];
		}

		/* Iota */
		st[0] ^= keccakf_rndc[round];
	}
}
#endif //KECCAKF_MACRO

int sha3_init(struct sha3_ctx *ctx, unsigned int digest_sz)
{
	if (!ctx || (digest_sz != SHA3_224_DIGEST_SIZE
		       && digest_sz != SHA3_256_DIGEST_SIZE
		       && digest_sz != SHA3_384_DIGEST_SIZE
		       && digest_sz != SHA3_512_DIGEST_SIZE))
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->md_len = digest_sz;
	ctx->rsiz = 200 - 2 * digest_sz;
	ctx->rsizw = ctx->rsiz / 8;
	
	return 0;
}

int sha3_update(struct sha3_ctx *ctx, const void *data,
		       unsigned int len)
{
	unsigned int done;
	const void *src;

	if (!ctx || !data)
		return -1;

	done = 0;
	src = data;

	if ((ctx->partial + len) > (ctx->rsiz - 1)) {
		if (ctx->partial) {
			done = -ctx->partial;
			memcpy(ctx->buf + ctx->partial, data,
			       done + ctx->rsiz);
			src = ctx->buf;
		}

		do {
			unsigned int i;

			for (i = 0; i < ctx->rsizw; i++)
				ctx->st[i] ^= ((uint64_t *) src)[i];
			keccakf(ctx->st);

			done += ctx->rsiz;
			src = data + done;
		} while (done + (ctx->rsiz - 1) < len);

		ctx->partial = 0;
	}
	memcpy(ctx->buf + ctx->partial, src, len - done);
	ctx->partial += (len - done);

	return 0;
}

int sha3_final(struct sha3_ctx *ctx, void *out, unsigned int outlen)
{
	unsigned int i, inlen;

	if (!ctx || !out || (outlen != SHA3_224_DIGEST_SIZE
		  		&& outlen != SHA3_256_DIGEST_SIZE
		  		&& outlen != SHA3_384_DIGEST_SIZE
		  		&& outlen != SHA3_512_DIGEST_SIZE))
		return -1;
	
	inlen = ctx->partial;
	ctx->buf[inlen++] = 0x06;
	memset(ctx->buf + inlen, 0, ctx->rsiz - inlen);
	ctx->buf[ctx->rsiz - 1] |= 0x80;

	for (i = 0; i < ctx->rsizw; i++)
		ctx->st[i] ^= ((uint64_t *) ctx->buf)[i];

	keccakf(ctx->st);

	//for (i = 0; i < ctx->rsizw; i++)
	//	ctx->st[i] = cpu_to_le64(ctx->st[i]);

	memcpy(out, ctx->st, ctx->md_len);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

