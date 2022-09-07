/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __MD2_H__
#define __MD2_H__

#include "utils.h"

#define MD2_STATE_SIZE   16
#define MD2_BLOCK_SIZE   16
#define MD2_DIGEST_SIZE  16
#define MD2_DIGEST_SIZE_BITS  128

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < MD2_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE MD2_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < MD2_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS MD2_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < MD2_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE MD2_BLOCK_SIZE
#endif

#define MD2_HASH_MAGIC ((uint64_t)(0x8432927137264770ULL))
#define MD2_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == MD2_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t md2_total;
	/* Internal state */
	uint8_t md2_state[MD2_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t md2_buffer[MD2_BLOCK_SIZE];
	/* Internal buffer to hold the checksum */
	uint8_t md2_checksum[MD2_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} md2_context;


/* Init hash function. Returns 0 on success, -1 on error. */
int md2_init(md2_context *ctx);

int md2_update(md2_context *ctx, const uint8_t *input, uint32_t ilen);

/* Finalize. Returns 0 on success, -1 on error.*/
int md2_final(md2_context *ctx, uint8_t output[MD2_DIGEST_SIZE]);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int md2_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MD2_DIGEST_SIZE]);

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int md2(const uint8_t *input, uint32_t ilen, uint8_t output[MD2_DIGEST_SIZE]);

#endif /* __MD2_H__ */
