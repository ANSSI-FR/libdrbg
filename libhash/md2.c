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

#ifdef WITH_HASH_MD2

#include "md2.h"

/* All the inner MD-2 operations */
static const uint8_t PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

/* MD-2 core processing. Returns 0 on success, -1 on error. */
static inline int md2_process(md2_context *ctx,
			   const uint8_t data[MD2_BLOCK_SIZE])
{
	int ret;
	unsigned int i, j, t;
	uint8_t x[3 * MD2_BLOCK_SIZE];

	MUST_HAVE((data != NULL), ret, err);
	MD2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Form state, block, state ^ block */
	memcpy(&x[0], ctx->md2_state, MD2_BLOCK_SIZE);
	memcpy(&x[MD2_BLOCK_SIZE], data, MD2_BLOCK_SIZE);
	for(i = 0; i < MD2_BLOCK_SIZE; i++){
		x[(2 * MD2_BLOCK_SIZE) + i] = (ctx->md2_state[i] ^ data[i]);
	}
	/* Encrypt the block during 18 rounds */
	t = 0;
	for(i = 0; i < 18; i++){
		for (j = 0; j < (3 * MD2_BLOCK_SIZE); j++){
			x[j] ^= PI_SUBST[t];
			t = x[j];
		}
		t = (t + i) & 0xff;
	}
	/* Save the new state */
	memcpy(ctx->md2_state, &x[0], MD2_BLOCK_SIZE);
	/* Update the checksum */
	t = ctx->md2_checksum[MD2_BLOCK_SIZE - 1];
	for(i = 0; i < MD2_BLOCK_SIZE; i++){
		ctx->md2_checksum[i] ^= PI_SUBST[data[i] ^ t];
		t = ctx->md2_checksum[i];
	}

	/* Zeroize x as not needed anymore */
	memset(x, 0, sizeof(x));

	ret = 0;

err:
	return ret;
}

/* Init hash function. Returns 0 on success, -1 on error. */
int md2_init(md2_context *ctx)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	ctx->md2_total = 0;
	/* Zeroize the state */
	memset(ctx->md2_state, 0, sizeof(ctx->md2_state));
	/* Zeroize the checksum */
	memset(ctx->md2_checksum, 0, sizeof(ctx->md2_checksum));

	/* Tell that we are initialized */
	ctx->magic = MD2_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

int md2_update(md2_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;

	MUST_HAVE((input != NULL) || (ilen == 0), ret, err);
	MD2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->md2_total & 0xF);
	fill = (uint16_t)(MD2_BLOCK_SIZE - left);

	ctx->md2_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(ctx->md2_buffer + left, data_ptr, fill);
		ret = md2_process(ctx, ctx->md2_buffer); EG(ret, err);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= MD2_BLOCK_SIZE) {
		ret = md2_process(ctx, data_ptr); EG(ret, err);
		data_ptr += MD2_BLOCK_SIZE;
		remain_ilen -= MD2_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		memcpy(ctx->md2_buffer + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize. Returns 0 on success, -1 on error.*/
int md2_final(md2_context *ctx, uint8_t output[MD2_DIGEST_SIZE])
{
	int ret;
	unsigned int i;
	uint8_t pad_byte;

	MUST_HAVE((output != NULL), ret, err);
	MD2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* This is our final step, so we proceed with the padding */
	pad_byte = (uint8_t)(MD2_BLOCK_SIZE - (ctx->md2_total % MD2_BLOCK_SIZE));
	for(i = (ctx->md2_total % MD2_BLOCK_SIZE); i < MD2_BLOCK_SIZE; i++){
		ctx->md2_buffer[i] = pad_byte;
	}
	/* And process the block */
	ret = md2_process(ctx, ctx->md2_buffer); EG(ret, err);

	/* Also process the checksum */
	ret = md2_process(ctx, ctx->md2_checksum); EG(ret, err);

	/* Output the hash result */
	memcpy(output, ctx->md2_state, MD2_DIGEST_SIZE);

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
int md2_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MD2_DIGEST_SIZE])
{
	md2_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = md2_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = md2_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = md2_final(&ctx, output);

err:
	return ret;
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int md2(const uint8_t *input, uint32_t ilen, uint8_t output[MD2_DIGEST_SIZE])
{
	md2_context ctx;
	int ret;

	ret = md2_init(&ctx); EG(ret, err);
	ret = md2_update(&ctx, input, ilen); EG(ret, err);
	ret = md2_final(&ctx, output);

err:
	return ret;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
