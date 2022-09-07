/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHAKE_H__
#define __SHAKE_H__

#include "utils.h"
#include "keccak.h"

typedef enum {
	SHAKE_LITTLE = 0,
	SHAKE_BIG = 1,
} shake_endianness;
/*
 * Generic context for all SHAKE instances. Only difference is digest size
 * value, initialized in init() call and used in finalize().
 */
typedef struct shake_context_ {
	uint8_t shake_digest_size;
	uint8_t shake_block_size;
	shake_endianness shake_endian;
	/* Local index, useful for the absorbing phase */
	uint64_t shake_idx;
	/* Keccak's state, viewed as a bi-dimensional array */
	uint64_t shake_state[KECCAK_SLICES * KECCAK_SLICES];
	/* Initialization magic value */
	uint64_t magic;
} shake_context;


int _shake_init(shake_context *ctx, uint8_t digest_size, uint8_t block_size);
int _shake_update(shake_context *ctx, const uint8_t *buf, uint32_t buflen);
int _shake_finalize(shake_context *ctx, uint8_t *output);

#endif /* __SHAKE_H__ */
