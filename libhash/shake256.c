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

#ifdef WITH_HASH_SHAKE256

#include "shake256.h"

int shake256_init(shake256_context *ctx)
{
	int ret;

	ret = _shake_init(ctx, SHAKE256_DIGEST_SIZE, SHAKE256_BLOCK_SIZE); EG(ret, err);

	/* Tell that we are initialized */
	ctx->magic = SHAKE256_HASH_MAGIC;

err:
	return ret;
}

int shake256_update(shake256_context *ctx, const uint8_t *input, uint32_t ilen)
{
	int ret;

	SHAKE256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = _shake_update((shake_context *)ctx, input, ilen);

err:
	return ret;
}

int shake256_final(shake256_context *ctx, uint8_t output[SHAKE256_DIGEST_SIZE])
{
	int ret;

	SHAKE256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = _shake_finalize((shake_context *)ctx, output);

	/* Tell that we are uninitialized */
	ctx->magic = (uint64_t)0;

err:
	return ret;
}

int shake256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			uint8_t output[SHAKE256_DIGEST_SIZE])
{
	shake256_context ctx;
	int pos = 0, ret;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = shake256_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = shake256_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = shake256_final(&ctx, output);

err:
	return ret;
}

int shake256(const uint8_t *input, uint32_t ilen, uint8_t output[SHAKE256_DIGEST_SIZE])
{
	int ret;
	shake256_context ctx;

	ret = shake256_init(&ctx); EG(ret, err);
	ret = shake256_update(&ctx, input, ilen); EG(ret, err);
	ret = shake256_final(&ctx, output);

err:
	return ret;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
