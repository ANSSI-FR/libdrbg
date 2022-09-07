/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "libhash_config.h"

#ifdef WITH_HASH_SHA0

#include "sha0.h"

#define ROTL_SHA0(x, n)      ((((uint32_t)(x)) << (n)) | (((uint32_t)(x)) >> (32-(n))))

/* All the inner SHA-0 operations */
#define K1_SHA0	0x5a827999
#define K2_SHA0	0x6ed9eba1
#define K3_SHA0	0x8f1bbcdc
#define K4_SHA0	0xca62c1d6

#define F1_SHA0(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define F2_SHA0(x, y, z)   ((x) ^ (y) ^ (z))
#define F3_SHA0(x, y, z)   (((x) & (y)) | ((z) & ((x) | (y))))
#define F4_SHA0(x, y, z)   ((x) ^ (y) ^ (z))

#define SHA0_EXPAND(W, i) (W[i & 15] = (W[i & 15] ^ W[(i - 14) & 15] ^ W[(i - 8) & 15] ^ W[(i - 3) & 15]))

#define SHA0_SUBROUND(a, b, c, d, e, F, K, data) do { \
	uint32_t A_, B_, C_, D_, E_; \
	A_ = (e + ROTL_SHA0(a, 5) + F(b, c, d) + K + data); \
	B_ = a; \
	C_ = ROTL_SHA0(b, 30); \
	D_ = c; \
	E_ = d; \
	/**/ \
	a = A_; b = B_; c = C_; d = D_; e = E_; \
} while(0)

/* SHA-0 core processing. Returns 0 on success, -1 on error. */
static inline int sha0_process(sha0_context *ctx,
			   const uint8_t data[SHA0_BLOCK_SIZE])
{
	uint32_t A, B, C, D, E;
	uint32_t W[16];
	int ret;
	unsigned int i;

	MUST_HAVE((data != NULL), ret, err);
	SHA0_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Init our inner variables */
	A = ctx->sha0_state[0];
	B = ctx->sha0_state[1];
	C = ctx->sha0_state[2];
	D = ctx->sha0_state[3];
	E = ctx->sha0_state[4];

	/* Load data */
	for (i = 0; i < 16; i++) {
		GET_UINT32_BE(W[i], data, (4 * i));
	}
	for (i = 0; i < 80; i++) {
		if(i <= 15){
			SHA0_SUBROUND(A, B, C, D, E, F1_SHA0, K1_SHA0, W[i]);
		}
		else if((i >= 16) && (i <= 19)){
			SHA0_SUBROUND(A, B, C, D, E, F1_SHA0, K1_SHA0, SHA0_EXPAND(W, i));
		}
		else if((i >= 20) && (i <= 39)){
			SHA0_SUBROUND(A, B, C, D, E, F2_SHA0, K2_SHA0, SHA0_EXPAND(W, i));
		}
		else if((i >= 40) && (i <= 59)){
			SHA0_SUBROUND(A, B, C, D, E, F3_SHA0, K3_SHA0, SHA0_EXPAND(W, i));
		}
		else{
			SHA0_SUBROUND(A, B, C, D, E, F4_SHA0, K4_SHA0, SHA0_EXPAND(W, i));
		}
	}

	/* Update state */
	ctx->sha0_state[0] += A;
	ctx->sha0_state[1] += B;
	ctx->sha0_state[2] += C;
	ctx->sha0_state[3] += D;
	ctx->sha0_state[4] += E;

	ret = 0;

err:
	return ret;
}

/* Init hash function. Returns 0 on success, -1 on error. */
int sha0_init(sha0_context *ctx)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	ctx->sha0_total = 0;
	ctx->sha0_state[0] = 0x67452301;
	ctx->sha0_state[1] = 0xefcdab89;
	ctx->sha0_state[2] = 0x98badcfe;
	ctx->sha0_state[3] = 0x10325476;
	ctx->sha0_state[4] = 0xc3d2e1f0;

	/* Tell that we are initialized */
	ctx->magic = SHA0_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

int sha0_update(sha0_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;

	MUST_HAVE((input != NULL) || (ilen == 0), ret, err);
	SHA0_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->sha0_total & 0x3F);
	fill = (uint16_t)(SHA0_BLOCK_SIZE - left);

	ctx->sha0_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(ctx->sha0_buffer + left, data_ptr, fill);
		ret = sha0_process(ctx, ctx->sha0_buffer); EG(ret, err);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= SHA0_BLOCK_SIZE) {
		ret = sha0_process(ctx, data_ptr); EG(ret, err);
		data_ptr += SHA0_BLOCK_SIZE;
		remain_ilen -= SHA0_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		memcpy(ctx->sha0_buffer + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize. Returns 0 on success, -1 on error.*/
int sha0_final(sha0_context *ctx, uint8_t output[SHA0_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	uint8_t last_padded_block[2 * SHA0_BLOCK_SIZE];
	int ret;

	MUST_HAVE((output != NULL), ret, err);
	SHA0_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Fill in our last block with zeroes */
	memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = ctx->sha0_total % SHA0_BLOCK_SIZE;
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		memcpy(last_padded_block, ctx->sha0_buffer,
			     block_present);
	}

	/* Put the 0x80 byte, beginning of padding  */
	last_padded_block[block_present] = 0x80;

	/* Handle possible additional block */
	if (block_present > (SHA0_BLOCK_SIZE - 1 - sizeof(uint64_t))) {
		/* We need an additional block */
		PUT_UINT64_BE(8 * ctx->sha0_total, last_padded_block,
			      (2 * SHA0_BLOCK_SIZE) - sizeof(uint64_t));
		ret = sha0_process(ctx, last_padded_block); EG(ret, err);
		ret = sha0_process(ctx, last_padded_block + SHA0_BLOCK_SIZE); EG(ret, err);
	} else {
		/* We do not need an additional block */
		PUT_UINT64_BE(8 * ctx->sha0_total, last_padded_block,
			      SHA0_BLOCK_SIZE - sizeof(uint64_t));
		ret = sha0_process(ctx, last_padded_block); EG(ret, err);
	}

	/* Output the hash result */
	PUT_UINT32_BE(ctx->sha0_state[0], output, 0);
	PUT_UINT32_BE(ctx->sha0_state[1], output, 4);
	PUT_UINT32_BE(ctx->sha0_state[2], output, 8);
	PUT_UINT32_BE(ctx->sha0_state[3], output, 12);
	PUT_UINT32_BE(ctx->sha0_state[4], output, 16);

	/* Tell that we are uninitialized */
	ctx->magic = (uint64_t)0;

	ret = 0;

err:
	return ret;
}


/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int sha0_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[SHA0_DIGEST_SIZE])
{
	sha0_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = sha0_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = sha0_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = sha0_final(&ctx, output);

err:
	return ret;
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int sha0(const uint8_t *input, uint32_t ilen, uint8_t output[SHA0_DIGEST_SIZE])
{
	sha0_context ctx;
	int ret;

	ret = sha0_init(&ctx); EG(ret, err);
	ret = sha0_update(&ctx, input, ilen); EG(ret, err);
	ret = sha0_final(&ctx, output);

err:
	return ret;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
