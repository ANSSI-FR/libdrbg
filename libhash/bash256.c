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

#ifdef WITH_HASH_BASH256

#include "bash256.h"

/* Init hash function. Returns 0 on success, -1 on error. */
int bash256_init(bash256_context *ctx)
{
	int ret;

	ret = _bash_init(ctx, BASH256_DIGEST_SIZE); EG(ret, err);

	/* Tell that we are initialized */
	ctx->magic = BASH256_HASH_MAGIC;

err:
	return ret;
}

/* Update hash function. Returns 0 on success, -1 on error. */
int bash256_update(bash256_context *ctx, const uint8_t *input, uint32_t ilen)
{
	int ret;

	BASH256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = _bash_update((bash_context *)ctx, input, ilen);

err:
	return ret;
}

/* Finalize hash function. Returns 0 on success, -1 on error. */
int bash256_final(bash256_context *ctx, uint8_t output[BASH256_DIGEST_SIZE])
{
	int ret;

	BASH256_HASH_CHECK_INITIALIZED(ctx, ret, err);

	ret = _bash_finalize((bash_context *)ctx, output); EG(ret, err);

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
int bash256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			uint8_t output[BASH256_DIGEST_SIZE])
{
	bash256_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = bash256_init(&ctx); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = bash256_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = bash256_final(&ctx, output);

err:
	return ret;
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int bash256(const uint8_t *input, uint32_t ilen, uint8_t output[BASH256_DIGEST_SIZE])
{
	bash256_context ctx;
	int ret;

	ret = bash256_init(&ctx); EG(ret, err);
	ret = bash256_update(&ctx, input, ilen); EG(ret, err);
	ret = bash256_final(&ctx, output); EG(ret, err);

err:
	return ret;
}

#else /* WITH_HASH_BASH256 */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_BASH256 */
