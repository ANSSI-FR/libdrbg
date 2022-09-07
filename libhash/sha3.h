/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA3_H__
#define __SHA3_H__

#include "keccak.h"

typedef enum {
	SHA3_LITTLE = 0,
	SHA3_BIG = 1,
} sha3_endianness;
/*
 * Generic context for all SHA3 instances. Only difference is digest size
 * value, initialized in init() call and used in finalize().
 */
typedef struct sha3_context_ {
	uint8_t sha3_digest_size;
	uint8_t sha3_block_size;
	sha3_endianness sha3_endian;
	/* Local index, useful for the absorbing phase */
	uint64_t sha3_idx;
	/* Keccak's state, viewed as a bi-dimensional array */
	uint64_t sha3_state[KECCAK_SLICES * KECCAK_SLICES];
	/* Initialization magic value */
	uint64_t magic;
} sha3_context;


int _sha3_init(sha3_context *ctx, uint8_t digest_size);
int _sha3_update(sha3_context *ctx, const uint8_t *buf, uint32_t buflen);
int _sha3_finalize(sha3_context *ctx, uint8_t *output);

#endif /* __SHA3_H__ */
