/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __MDC2_H__
#define __MDC2_H__

#include "utils.h"

#define MDC2_STATE_SIZE   16
#define MDC2_BLOCK_SIZE   8
#define MDC2_DIGEST_SIZE  16
#define MDC2_DIGEST_SIZE_BITS  128

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < MDC2_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE MDC2_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < MDC2_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS MDC2_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < MDC2_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE MDC2_BLOCK_SIZE
#endif

#define MDC2_HASH_MAGIC ((uint64_t)(0x8296527183648310ULL))
#define MDC2_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == MDC2_HASH_MAGIC), ret, err)

/* Padding types as described in the informative appendix of
 * ISO-IEC-10118-2-1994
 */
typedef enum {
	ISOIEC10118_TYPE1 = 0,
	ISOIEC10118_TYPE2 = 1,
} padding_type;

typedef struct {
	/* Number of bytes processed */
	uint64_t mdc2_total;
	/* Internal state */
	uint8_t mdc2_state[MDC2_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t mdc2_buffer[MDC2_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
	/* Padding type, as per ISO-IEC-10118-2-1994 */
	padding_type padding;
} mdc2_context;

int mdc2_set_padding_type(mdc2_context *ctx,
							padding_type p);

/* Init hash function. Returns 0 on success, -1 on error. */
int mdc2_init(mdc2_context *ctx);

int mdc2_update(mdc2_context *ctx, const uint8_t *input, uint32_t ilen);

/* Finalize. Returns 0 on success, -1 on error.*/
int mdc2_final(mdc2_context *ctx, uint8_t output[MDC2_DIGEST_SIZE]);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int mdc2_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE], padding_type p);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int mdc2_scattered_padding1(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE]);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int mdc2_scattered_padding2(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE]);
/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE], padding_type p);

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2_padding1(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE]);

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2_padding2(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE]);

#endif /* __MDC2_H__ */
