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

#if defined(WITH_HASH_STREEBOG256) || defined(WITH_HASH_STREEBOG512)

/*
 * NOTE: we put STREEBOG256 and STREEBOG512 in the same compilation unit on
 * purpose, so that we avoid duplicating the rather big tables that are shared
 * between the two digest versions.
 */

#ifdef WITH_HASH_STREEBOG256
#include "streebog256.h"
#endif
#ifdef WITH_HASH_STREEBOG512
#include "streebog512.h"
#endif

/*** Generic functions for both STREEBOG256 and STREEBOG512 ***/
/* Init */
static int streebog_init(streebog_context *ctx, uint8_t digest_size, uint8_t block_size)
{
	int ret;

	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64), ret, err);

	MUST_HAVE((ctx != NULL), ret, err);

	/* Zeroize the internal state */
	memset(ctx, 0, sizeof(streebog_context));

	if(digest_size == 32){
		memset(ctx->h, 1, sizeof(ctx->h));
	}

	/* Initialize our digest size and block size */
	ctx->streebog_digest_size = digest_size;
	ctx->streebog_block_size = block_size;
	/* Detect endianness */
	ctx->streebog_endian = arch_is_big_endian() ? STREEBOG_BIG : STREEBOG_LITTLE;

	ret = 0;

err:
	return ret;
}

static int streebog_update(streebog_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;

	MUST_HAVE((ctx != NULL) && ((input != NULL) || (ilen == 0)), ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->streebog_total & 0x3F);
	fill = (uint16_t)(STREEBOG_BLOCK_SIZE - left);

	ctx->streebog_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(ctx->streebog_buffer + left, data_ptr, fill);
		streebog_process(ctx, ctx->streebog_buffer, (8 * STREEBOG_BLOCK_SIZE));
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= STREEBOG_BLOCK_SIZE) {
		streebog_process(ctx, data_ptr, (8 * STREEBOG_BLOCK_SIZE));
		data_ptr += STREEBOG_BLOCK_SIZE;
		remain_ilen -= STREEBOG_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		memcpy(ctx->streebog_buffer + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

static int streebog_final(streebog_context *ctx, uint8_t *output)
{
	unsigned int block_present = 0;
	uint8_t last_padded_block[STREEBOG_BLOCK_SIZE];
	uint64_t Z[STREEBOG_BLOCK_U64_SIZE];
	unsigned int j;
	uint8_t digest_size;
	uint8_t idx;
	int ret;

	MUST_HAVE((ctx != NULL) && (output != NULL), ret, err);

	digest_size = ctx->streebog_digest_size;
	/* Sanity check */
	MUST_HAVE((digest_size == 32) || (digest_size == 64), ret, err);

	/* Zero init our Z */
	memset(Z, 0, sizeof(Z));

	/* Fill in our last block with zeroes */
	memset(last_padded_block, 0, sizeof(last_padded_block));

	/* This is our final step, so we proceed with the padding */
	block_present = (ctx->streebog_total % STREEBOG_BLOCK_SIZE);
	if (block_present != 0) {
		/* Copy what's left in our temporary context buffer */
		memcpy(last_padded_block, ctx->streebog_buffer,
			     block_present);
	}

	/* Put the 0x01 byte, beginning of padding  */
	last_padded_block[block_present] = 0x01;

	streebog_process(ctx, last_padded_block, (8 * (ctx->streebog_total % STREEBOG_BLOCK_SIZE)));

	gN(ctx->h, ctx->N, Z);
	gN(ctx->h, ctx->Sigma, Z);

	for(j = 0; j < STREEBOG_BLOCK_U64_SIZE; j++){
		ctx->h[j] = S64(ctx->h[j]);
	}

	idx = 0;

	if(digest_size == 64){
		/* 512-bit hash case */
		STREEBOG_PUT_UINT64(ctx->h[0], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
		STREEBOG_PUT_UINT64(ctx->h[1], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
		STREEBOG_PUT_UINT64(ctx->h[2], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
		STREEBOG_PUT_UINT64(ctx->h[3], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
	}
	/* 256 and 512-bit hash case */
	STREEBOG_PUT_UINT64(ctx->h[4], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
	STREEBOG_PUT_UINT64(ctx->h[5], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
	STREEBOG_PUT_UINT64(ctx->h[6], output, idx, ctx->streebog_endian); idx = (uint8_t)(idx + 8);
	STREEBOG_PUT_UINT64(ctx->h[7], output, idx, ctx->streebog_endian);

	ret = 0;

err:
	return ret;
}

#ifdef WITH_HASH_STREEBOG256
/* Init */
int streebog256_init(streebog256_context *ctx)
{
	int ret;

	ret = streebog_init(ctx, STREEBOG256_DIGEST_SIZE, STREEBOG256_BLOCK_SIZE); EG(ret, err);

	ctx->magic = STREEBOG256_HASH_MAGIC;

err:
	return ret;
}

/* Update */
int streebog256_update(streebog256_context *ctx, const uint8_t *input, uint32_t ilen)
{
	int ret;

	STREEBOG256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = streebog_update(ctx, input, ilen);

err:
	return ret;
}

/* Finalize */
int streebog256_final(streebog256_context *ctx,
		       uint8_t output[STREEBOG256_DIGEST_SIZE])
{
	int ret;

	STREEBOG256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = streebog_final(ctx, output); EG(ret, err);

	/* Uninit our context magic */
	ctx->magic = (uint64_t)0;

	ret = 0;

err:
	return ret;
}

int streebog256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			   uint8_t output[STREEBOG256_DIGEST_SIZE])
{
	streebog256_context ctx;
	int pos = 0;
	int ret;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = streebog256_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = streebog256_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = streebog256_final(&ctx, output);

err:
	return ret;
}

int streebog256(const uint8_t *input, uint32_t ilen, uint8_t output[STREEBOG256_DIGEST_SIZE])
{
	int ret;
	streebog256_context ctx;

	ret = streebog256_init(&ctx); EG(ret, err);
	ret = streebog256_update(&ctx, input, ilen); EG(ret, err);
	ret = streebog256_final(&ctx, output);

err:
	return ret;
}
#endif

#ifdef WITH_HASH_STREEBOG512
/* Init */
int streebog512_init(streebog512_context *ctx)
{
	int ret;

	ret = streebog_init(ctx, STREEBOG512_DIGEST_SIZE, STREEBOG512_BLOCK_SIZE); EG(ret, err);

	ctx->magic = STREEBOG512_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

/* Update */
int streebog512_update(streebog512_context *ctx, const uint8_t *input, uint32_t ilen)
{
	int ret;

	STREEBOG512_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = streebog_update(ctx, input, ilen);

err:
	return ret;
}

/* Finalize */
int streebog512_final(streebog512_context *ctx,
		       uint8_t output[STREEBOG512_DIGEST_SIZE])
{
	int ret;

	STREEBOG512_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = streebog_final(ctx, output); EG(ret, err);

	/* Uninit our context magic */
	ctx->magic = (uint64_t)0;

	ret = 0;

err:
	return ret;
}

int streebog512_scattered(const uint8_t **inputs, const uint32_t *ilens,
			   uint8_t output[STREEBOG512_DIGEST_SIZE])
{
	streebog512_context ctx;
	int pos = 0;
	int ret;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = streebog512_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = streebog512_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = streebog512_final(&ctx, output);

err:
	return ret;
}

int streebog512(const uint8_t *input, uint32_t ilen, uint8_t output[STREEBOG512_DIGEST_SIZE])
{
	int ret;
	streebog512_context ctx;

	ret = streebog512_init(&ctx); EG(ret, err);
	ret = streebog512_update(&ctx, input, ilen); EG(ret, err);
	ret = streebog512_final(&ctx, output);

err:
	return ret;
}
#endif

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
