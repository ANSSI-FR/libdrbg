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

#ifdef WITH_HASH_MDC2

#include "mdc2.h"

/* Include DES helpers */
#include "tdes.h"

int mdc2_set_padding_type(mdc2_context *ctx,
			  padding_type p)
{
	int ret;

	MDC2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* We cannot change the padding type after the first update */
	MUST_HAVE((ctx->mdc2_total == 0), ret, err);

	if((p != ISOIEC10118_TYPE1) && (p != ISOIEC10118_TYPE2)){
		ret = -1;
		goto err;
	}

	ctx->padding = p;

	ret = 0;

err:
	return ret;
}

/* MDC-2 core processing. Returns 0 on success, -1 on error. */
static inline int mdc2_process(mdc2_context *ctx,
			       const uint8_t data[MDC2_BLOCK_SIZE])
{
	int ret;
	unsigned int j;
	uint8_t V[8], W[8];
	uint8_t *A, *B;
	des_context des_ctx;

	/* Get the current internal state in A and B */
	A = (uint8_t*)&(ctx->mdc2_state[0]);
	B = (uint8_t*)&(ctx->mdc2_state[8]);

	A[0] = (uint8_t)((A[0] & 0x9f) | 0x40);
	B[0] = (uint8_t)((B[0] & 0x9f) | 0x20);
	/* Set odd parity */
	for(j = 0; j < 8; j++){
		A[j] = odd_parity[A[j]];
		B[j] = odd_parity[B[j]];
	}
	/* Compute V_i = M_i + E(M_i, A_i) */
	memset(&des_ctx, 0, sizeof(des_context));
	ret = des_set_key(&des_ctx, A, DES_ENCRYPTION); EG(ret, err);
	ret = des(&des_ctx, &data[0], V); EG(ret, err);
	for(j = 0; j < 8; j++){
		V[j] = (V[j] ^ data[j]);
	}
	/* Compute W_i = M_i + E(M_i, B_i) */
	memset(&des_ctx, 0, sizeof(des_context));
	ret = des_set_key(&des_ctx, B, DES_ENCRYPTION); EG(ret, err);
	ret = des(&des_ctx, &data[0], W); EG(ret, err);
	for(j = 0; j < 8; j++){
		W[j] = (W[j] ^ data[j]);
	}
	/* Cross the results */
	/* In A */
	memcpy(&A[0], &V[0], 4);
	memcpy(&A[4], &W[4], 4);
	/* In B */
	memcpy(&B[0], &W[0], 4);
	memcpy(&B[4], &V[4], 4);

err:
	return ret;
}

/* Init hash function. Returns 0 on success, -1 on error. */
int mdc2_init(mdc2_context *ctx)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	ctx->mdc2_total = 0;
	/* Initialize A1 */
	memset(&(ctx->mdc2_state[0]), 0x52, 8);
	/* Initialize B1 */
	memset(&(ctx->mdc2_state[8]), 0x25, 8);
	/* Initialize default padding type */
	ctx->padding = ISOIEC10118_TYPE1;

	/* Tell that we are initialized */
	ctx->magic = MDC2_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

int mdc2_update(mdc2_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;

	MUST_HAVE((input != NULL) || (ilen == 0), ret, err);
	MDC2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->mdc2_total & 0xF);
	fill = (uint16_t)(MDC2_BLOCK_SIZE - left);

	ctx->mdc2_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(ctx->mdc2_buffer + left, data_ptr, fill);
		ret = mdc2_process(ctx, ctx->mdc2_buffer); EG(ret, err);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= MDC2_BLOCK_SIZE) {
		ret = mdc2_process(ctx, data_ptr); EG(ret, err);
		data_ptr += MDC2_BLOCK_SIZE;
		remain_ilen -= MDC2_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		memcpy(ctx->mdc2_buffer + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize. Returns 0 on success, -1 on error.*/
int mdc2_final(mdc2_context *ctx, uint8_t output[MDC2_DIGEST_SIZE])
{
	int ret;
	unsigned int i;
	uint8_t pad_byte;

	MUST_HAVE((output != NULL), ret, err);
	MDC2_HASH_CHECK_INITIALIZED(ctx, ret, err);

	if(ctx->padding == ISOIEC10118_TYPE1){
		/* "Padding method 1" in ISO-IEC-10118 */
		/* This is our final step, so we proceed with the padding: the last block
		 * is padded with zeroes.
		 */
		pad_byte = 0x00;
		if((ctx->mdc2_total % MDC2_BLOCK_SIZE) != 0){
			for(i = (ctx->mdc2_total % MDC2_BLOCK_SIZE); i < MDC2_BLOCK_SIZE; i++){
				ctx->mdc2_buffer[i] = pad_byte;
			}
			/* And process the block */
			ret = mdc2_process(ctx, ctx->mdc2_buffer); EG(ret, err);
		}
	}
	else if(ctx->padding == ISOIEC10118_TYPE2){
		/* "Padding method 2" in ISO-IEC-10118 */
		/* This is our final step, so we proceed with the padding: the last block
		 * is appended 0x80 and then padded with zeroes.
		 */
		ctx->mdc2_buffer[(ctx->mdc2_total % MDC2_BLOCK_SIZE)] = 0x80;
		pad_byte = 0x00;
		for(i = ((unsigned int)(ctx->mdc2_total % MDC2_BLOCK_SIZE) + 1); i < MDC2_BLOCK_SIZE; i++){
			ctx->mdc2_buffer[i] = pad_byte;
		}
		/* And process the block */
		ret = mdc2_process(ctx, ctx->mdc2_buffer); EG(ret, err);
	}
	else{
		/* Unkown padding */
		ret = -1;
		goto err;
	}

	/* Output the hash result */
	memcpy(output, ctx->mdc2_state, MDC2_DIGEST_SIZE);

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
int mdc2_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE], padding_type p)
{
	mdc2_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = mdc2_init(&ctx); EG(ret, err);

	ret = mdc2_set_padding_type(&ctx, p); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = mdc2_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = mdc2_final(&ctx, output);

err:
	return ret;
}

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int mdc2_scattered_padding1(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE])
{
	return mdc2_scattered(inputs, ilens, output, ISOIEC10118_TYPE1);
}

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int mdc2_scattered_padding2(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[MDC2_DIGEST_SIZE])
{
	return mdc2_scattered(inputs, ilens, output, ISOIEC10118_TYPE2);
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE], padding_type p)
{
	mdc2_context ctx;
	int ret;

	ret = mdc2_init(&ctx); EG(ret, err);
	ret = mdc2_set_padding_type(&ctx, p); EG(ret, err);
	ret = mdc2_update(&ctx, input, ilen); EG(ret, err);
	ret = mdc2_final(&ctx, output);

err:
	return ret;
}


/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2_padding1(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE])
{
	return mdc2(input, ilen, output, ISOIEC10118_TYPE1);
}

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int mdc2_padding2(const uint8_t *input, uint32_t ilen, uint8_t output[MDC2_DIGEST_SIZE])
{
	return mdc2(input, ilen, output, ISOIEC10118_TYPE2);
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
