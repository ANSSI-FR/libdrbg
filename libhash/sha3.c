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

#if defined(WITH_HASH_SHA3_224) || defined(WITH_HASH_SHA3_256) || defined(WITH_HASH_SHA3_384) || defined(WITH_HASH_SHA3_512)

#include "sha3.h"

/* Init function depending on the digest size. Return 0 on success, -1 on error. */
int _sha3_init(sha3_context *ctx, uint8_t digest_size)
{
	int ret;

	/*
	 * Check given inpur digest size: we only consider KECCAK versions
	 * mapped on SHA-3 instances (224, 256, 384, 512).
	 */
	MUST_HAVE(((digest_size == (224/8)) || (digest_size == (256/8)) ||
		   (digest_size == (384/8)) || (digest_size == (512/8))), ret, err);
	MUST_HAVE((ctx != NULL), ret, err);

	/* Zeroize the internal state */
	memset(ctx->sha3_state, 0, sizeof(ctx->sha3_state));

	ctx->sha3_idx = 0;
	ctx->sha3_digest_size = digest_size;
	ctx->sha3_block_size = (uint8_t)((KECCAK_SLICES * KECCAK_SLICES * sizeof(uint64_t)) - (uint8_t)(2 * digest_size));

	/* Detect endianness */
	ctx->sha3_endian = arch_is_big_endian() ? SHA3_BIG : SHA3_LITTLE;

	ret = 0;

err:
	return ret;
}

/* Update hash function. Returns 0 on sucess, -1 on error. */
int _sha3_update(sha3_context *ctx, const uint8_t *input, uint32_t ilen)
{
	uint32_t i;
	uint8_t *state;
	int ret;

	MUST_HAVE(((ctx != NULL) && ((input != NULL) || (ilen == 0))), ret, err);

	state = (uint8_t*)(ctx->sha3_state);

	for (i = 0; i < ilen; i++) {
		uint64_t idx = (ctx->sha3_endian == SHA3_LITTLE) ? ctx->sha3_idx : SWAP64_Idx(ctx->sha3_idx);
		ctx->sha3_idx++;
		/* Update the state, and adapt endianness order */
		state[idx] ^= input[i];
		if(ctx->sha3_idx == ctx->sha3_block_size){
			KECCAKF(ctx->sha3_state);
			ctx->sha3_idx = 0;
		}
	}

	ret = 0;

err:
	return ret;
}

/* Finalize hash function. Returns 0 on success, -1 on error. */
int _sha3_finalize(sha3_context *ctx, uint8_t *output)
{
	unsigned int i;
	uint8_t *state;
	int ret;

	MUST_HAVE((output != NULL) && (ctx != NULL), ret, err);
	MUST_HAVE((ctx->sha3_digest_size <= sizeof(ctx->sha3_state)), ret, err);

	state = (uint8_t*)(ctx->sha3_state);

	/* Proceed with the padding of the last block */
	/* Compute the index depending on the endianness */
	if (ctx->sha3_endian == SHA3_LITTLE) {
		/* Little endian case */
		state[ctx->sha3_idx] ^= 0x06;
		state[ctx->sha3_block_size - 1] ^= 0x80;
	} else {
		/* Big endian case */
		state[SWAP64_Idx(ctx->sha3_idx)] ^= 0x06;
		state[SWAP64_Idx(ctx->sha3_block_size - 1)] ^= 0x80;
	}
	KECCAKF(ctx->sha3_state);
	for(i = 0; i < ctx->sha3_digest_size; i++){
		output[i] = (ctx->sha3_endian == SHA3_LITTLE) ? state[i] : state[SWAP64_Idx(i)];
	}

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
