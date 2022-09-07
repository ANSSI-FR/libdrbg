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

#if defined(WITH_HASH_BASH224) || defined(WITH_HASH_BASH256) || defined(WITH_HASH_BASH384) || defined(WITH_HASH_BASH512)

#include "bash.h"

/*
 * This is an implementation of the BASH hash functions family (for sizes 224, 256, 384 and 512)
 * following the standard STB 34.101.77-2020 (http://apmi.bsu.by/assets/files/std/bash-spec24.pdf).
 * An english version of the specifications exist here: https://eprint.iacr.org/2016/587.pdf
 */

int _bash_init(bash_context *ctx, uint8_t digest_size)
{
	int ret;
	uint8_t *state = NULL;

	/*
	 * Check given inpur digest size: we only consider BASH versions
	 * mapped on instances (224, 256, 384, 512).
	 */
	MUST_HAVE(((digest_size == (224/8)) || (digest_size == (256/8)) ||
		   (digest_size == (384/8)) || (digest_size == (512/8))), ret, err);
	MUST_HAVE((ctx != NULL), ret, err);

	state = (uint8_t*)(ctx->bash_state);

	/* Zeroize the internal state */
	memset(state, 0, sizeof(ctx->bash_state));

	ctx->bash_total = 0;
	ctx->bash_digest_size = digest_size;
	ctx->bash_block_size = (uint8_t)((BASH_SLICES_X * BASH_SLICES_Y * sizeof(uint64_t)) - (uint8_t)(2 * digest_size));

	/* Put <l / 4>64 at the end of the state */
	state[(BASH_SLICES_X * BASH_SLICES_Y * sizeof(uint64_t)) - sizeof(uint64_t)] = (uint8_t)digest_size;

	/* Detect endianness */
	ctx->bash_endian = arch_is_big_endian() ? BASH_BIG : BASH_LITTLE;

	ret = 0;

err:
	return ret;
}

int _bash_update(bash_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;
	uint8_t *state = NULL;

	MUST_HAVE(((ctx != NULL) && ((input != NULL) || (ilen == 0))), ret, err);

	state = (uint8_t*)(ctx->bash_state);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (uint8_t)(ctx->bash_total % ctx->bash_block_size);
	fill = (uint16_t)(ctx->bash_block_size - left);

	ctx->bash_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(state + left, data_ptr, fill);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
		BASHF(ctx->bash_state, ctx->bash_endian);
	}
	while (remain_ilen >= ctx->bash_block_size) {
		memcpy(state, data_ptr, ctx->bash_block_size);
		BASHF(ctx->bash_state, ctx->bash_endian);
		data_ptr += ctx->bash_block_size;
		remain_ilen -= ctx->bash_block_size;
	}
	if (remain_ilen > 0) {
		memcpy(state + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize hash function. Returns 0 on success, -1 on error. */
int _bash_finalize(bash_context *ctx, uint8_t *output)
{
	uint8_t pos;
	int ret;
	uint8_t *state = NULL;

	MUST_HAVE((ctx != NULL) && (output != NULL), ret, err);

	state = (uint8_t*)(ctx->bash_state);

	/* Handle the padding */
	pos = (uint8_t)(ctx->bash_total % ctx->bash_block_size);

	memset(state + pos, 0, (uint8_t)((ctx->bash_block_size) - pos));
	state[pos] = 0x40;

	BASHF(ctx->bash_state, ctx->bash_endian);

	/* Output the digest */
	memcpy(output, state, ctx->bash_digest_size);

	ret = 0;
err:
	return ret;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
