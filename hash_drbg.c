/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HASH_DRBG

#include "hash_drbg.h"

/* Specific Hash-DRBG data accessors */
#define DRBG_HASH_GET_DATA(ctx, d)		(ctx)->data.hash_data.d
#define DRBG_HASH_SET_DATA(ctx, d, s)		(ctx)->data.hash_data.d = (s)

#define DRBG_HASH_OPTIONS_GET_DATA(o, d)        (o)->opt.hash_options.d

/* HASH-DRBG for PRNG.
 * Standardized by NIST SP 800-90A.
 */

static drbg_error hash_drbg_check_initialized(drbg_ctx *ctx)
{
	drbg_error ret = HASH_DRBG_ERROR;

	if(ctx == NULL){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctx->engine_magic != HASH_DRBG_INIT_MAGIC){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}

	ret = HASH_DRBG_OK;

err:
	return ret;
}

static drbg_error hash_drbg_uninit(drbg_ctx *ctx)
{
	drbg_error ret = HASH_DRBG_ERROR;

	if((ctx == NULL) || (ctx->engine_magic != HASH_DRBG_INIT_MAGIC)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	ctx->engine_magic = 0x0;

	ret = HASH_DRBG_OK;

err:
	return ret;
}

static inline void hash_drbg_integer_sum(const uint8_t *A, const uint8_t *B,
					uint8_t *C, uint32_t size)
{
	integer_sum(A, B, C, size);

	return;
}

static inline void hash_drbg_integer_inc(const uint8_t *A, uint8_t *C,
					uint32_t size)
{
	integer_inc(A, C, size);

	return;
}

static drbg_error hash_drbg_hash(drbg_ctx *ctx,
				 const in_scatter_data *sc, unsigned int sc_num,
				 unsigned char *out_string, uint32_t outlen)
{
	drbg_error ret = HASH_DRBG_ERROR;
	hash_context h_ctx;
	unsigned int j;
	uint32_t digest_size;
	hash_alg_type hash_type;

	if(hash_drbg_check_initialized(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	/* Access specific data */
	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	hash_type   = DRBG_HASH_GET_DATA(ctx, hash_type);

	if((sc == NULL) || (out_string == NULL)){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(outlen != digest_size){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	if(hash_init(&h_ctx, hash_type)){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	for(j = 0; j < sc_num; j++){
		if(hash_update(&h_ctx, sc[j].data, sc[j].data_len, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
	}
	if(hash_final(&h_ctx, out_string, hash_type)){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	ret = HASH_DRBG_OK;

err:
	return ret;
}

/* The HASH-DRBG Hash_df derivation function*/
static drbg_error hash_drbg_hash_df(drbg_ctx *ctx,
				    const in_scatter_data *sc, unsigned int sc_num,
				    uint8_t *out_string, uint32_t outlen)
{
	drbg_error ret = HASH_DRBG_ERROR;
	uint32_t num;
	uint8_t num_bits_to_return[4] = { 0 };
	uint8_t counter;
	uint32_t remain;
	uint32_t digest_size, seed_len;
	hash_alg_type hash_type;

	if(hash_drbg_check_initialized(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	/* Access specific data */
	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	seed_len    = DRBG_HASH_GET_DATA(ctx, seed_len);
	hash_type   = DRBG_HASH_GET_DATA(ctx, hash_type);

	num = ((outlen % digest_size) == 0) ? (outlen / digest_size) : ((outlen / digest_size) + 1);

	if((sc == NULL) || (out_string == NULL)){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(seed_len > HASH_DRBG_MAX_SEED_LEN){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(num > 255){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	counter = 0x01;
	PUT_UINT32_BE((8 * outlen), num_bits_to_return, 0);
	remain = outlen;
	while(counter <= num){
		unsigned int j;
		hash_context h_ctx;
		if(hash_init(&h_ctx, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
		if(hash_update(&h_ctx, &counter, 1, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
		if(hash_update(&h_ctx, num_bits_to_return, 4, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
		for(j = 0; j < sc_num; j++){
			if(hash_update(&h_ctx, sc[j].data, sc[j].data_len, hash_type)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
		}

		/* Last block with remain? */
		if(remain < digest_size){
			uint8_t out_block[MAX_DIGEST_SIZE];
			if(hash_final(&h_ctx, out_block, hash_type)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
			memcpy(&out_string[(uint32_t)(counter - 1) * digest_size], out_block, remain);
			remain = 0;
		}
		else{
			if(hash_final(&h_ctx, &out_string[(uint32_t)(counter - 1) * digest_size], hash_type)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
			remain -= digest_size;
		}
		counter = (uint8_t)(counter + 1);
	}

	ret = HASH_DRBG_OK;
err:
	return ret;
}

/* The HASH-DRBG Hashgen function*/
static drbg_error hash_drbg_hashgen(drbg_ctx *ctx,
				    unsigned char *out_string, uint32_t outlen)
{
	drbg_error ret = HASH_DRBG_ERROR;
	hash_context h_ctx;
	uint32_t i, num, remain;
	uint8_t data[HASH_DRBG_MAX_SEED_LEN] = { 0 };
	uint32_t digest_size, seed_len;
	hash_alg_type hash_type;
	uint8_t *V;

	if(hash_drbg_check_initialized(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	/* Access specific data */
	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	seed_len    = DRBG_HASH_GET_DATA(ctx, seed_len);
	hash_type   = DRBG_HASH_GET_DATA(ctx, hash_type);
	V           = DRBG_HASH_GET_DATA(ctx, V);

	num = ((outlen % digest_size) == 0) ? (outlen / digest_size) : ((outlen / digest_size) + 1);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(seed_len > HASH_DRBG_MAX_SEED_LEN){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(out_string == NULL){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	/* NOTE: we should be ensured here that (num * digest_size) is at most one hash
	 * size more than outlen, so we have to deal with a hash size possible residue.
	 */

	/* data = V */
	memcpy(data, V, seed_len);
	remain = outlen;
	for(i = 0; i < num; i++){
		/* w = Hash (data) */
		if(hash_init(&h_ctx, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
		if(hash_update(&h_ctx, data, seed_len, hash_type)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
		/* W = W || w */
		if(remain < digest_size){
			uint8_t out_block[MAX_DIGEST_SIZE];
			if(hash_final(&h_ctx, out_block, hash_type)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
			memcpy(&out_string[i * digest_size], out_block, remain);
			remain = 0;
		}
		else{
			if(hash_final(&h_ctx, &out_string[i * digest_size], hash_type)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
			remain -= digest_size;
		}
		/* data = (data + 1) mod 2 seedlen */
		hash_drbg_integer_inc(data, data, seed_len);
	}

	ret = HASH_DRBG_OK;
err:
	return ret;
}


/* digest_size and block_size are returned in bytes and drbg_strength in bits */
static drbg_error hash_drbg_get_strength(hash_alg_type hash_type,
					 uint32_t *drbg_strength,
					 uint32_t *digest_size,
					 uint32_t *block_size)
{
	uint8_t ds, bs;
	drbg_error ret = HASH_DRBG_ERROR;

	if(drbg_strength == NULL){
		goto err;
	}

	if(hash_get_hash_sizes(hash_type, &ds, &bs)){
		goto err;
	}
	if(digest_size != NULL){
		(*digest_size) = ds;
	}
	if(block_size != NULL){
		(*block_size) = bs;
	}

	if(ds <= 20){
		/* 128 bits strength */
		(*drbg_strength) = 128;
	}
	else if(ds <= 28){
		/* 192 bits strength */
		(*drbg_strength) = 192;
	}
	else{
		/* 256 bits strength */
		(*drbg_strength) = 256;
	}

	ret = HASH_DRBG_OK;

err:
	return ret;
}

/* returned seed_len is in bits, not bytes */
static drbg_error hash_drbg_get_seed_len(hash_alg_type hash_type, uint32_t *seed_len)
{
	uint8_t ds, bs;
	drbg_error ret = HASH_DRBG_ERROR;

	if(seed_len == NULL){
		goto err;
	}

	if(hash_get_hash_sizes(hash_type, &ds, &bs)){
		goto err;
	}

	if(ds <= 32){
		/* Up to 256 bits output */
		(*seed_len) = HASH_DRBG_SEED_LEN_LOW;
	}
	else{
		/* More than 256 bits output */
		(*seed_len) = HASH_DRBG_SEED_LEN_HIGH;
	}
	if(((*seed_len) / 8) > HASH_DRBG_MAX_SEED_LEN){
		goto err;
	}

	ret = HASH_DRBG_OK;

err:
	return ret;
}

static drbg_error hash_drbg_check_instantiated(drbg_ctx *ctx)
{
	drbg_error ret = HASH_DRBG_NON_INIT;

	if((ret = hash_drbg_check_initialized(ctx)) != HASH_DRBG_OK){
		goto err;
	}
	if(ctx->engine_is_instantiated == false){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	/* Sanity check on the global DRBG type */
	if(ctx->type != DRBG_HASH){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}

	ret = HASH_DRBG_OK;

err:
	return ret;
}

static drbg_error hash_drbg_init(drbg_ctx *ctx,
				 hash_alg_type hash_type)
{
	drbg_error ret = HASH_DRBG_ERROR;
	uint32_t digest_size, seed_len;
	uint8_t *V, *C;

#ifdef STRICT_NIST_SP800_90A
	/* In "strict" NIST mode, we only support the approved algorithms in Table 2.
	 */
	unsigned int i;
	uint8_t found = 0;

	for(i = 0; i < (sizeof(nist_supported_hashes) / sizeof(hash_alg_type)); i++){
		if((hash_type == nist_supported_hashes[i]) && (hash_type != HASH_UNKNOWN_HASH_ALG)){
			found = 1;
			break;
		}
	}
	if(found == 0){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
#endif

	if(ctx == NULL){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(hash_type == HASH_UNKNOWN_HASH_ALG){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	DRBG_HASH_SET_DATA(ctx, hash_type, hash_type);
	/* Compute the strength */
	if((ret = hash_drbg_get_strength(hash_type, &(ctx->drbg_strength), &digest_size, NULL)) != HASH_DRBG_OK){
		goto err;
	}
	DRBG_HASH_SET_DATA(ctx, digest_size, digest_size);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	V = DRBG_HASH_GET_DATA(ctx, V);
	C = DRBG_HASH_GET_DATA(ctx, C);
	memset(C, 0, DRBG_HASH_C_SIZE);
	memset(V, 0, DRBG_HASH_V_SIZE);
	ctx->reseed_counter = 0;
	/* Initialize stuff provided by NIST SP800-90A in table 2 */
	ctx->reseed_interval          = HASH_DRBG_MAX_RESEED_INTERVAL;
	ctx->min_entropy_input_length = (ctx->drbg_strength / 8);
	ctx->max_entropy_input_length = (HASH_DRBG_MAX_ENTROPY_SIZE - 1);
	ctx->max_pers_string_length   = (HASH_DRBG_MAX_PERS_STRING_SIZE - 1);
	ctx->max_addin_length         = (HASH_DRBG_MAX_ADDIN_SIZE - 1);

	/* Compute the max asked length */
	ctx->max_asked_length = HASH_DRBG_MAX_ASKED_LENGTH;

	/* Compute the seedlen */
	if((ret = hash_drbg_get_seed_len(hash_type, &seed_len)) != HASH_DRBG_OK){
		goto err;
	}
	/* Seedlen in bits, to bytes */
	seed_len = (seed_len / 8);
	if(seed_len < 4){
		ret = HASH_DRBG_ERROR;
		goto err;
	}
	DRBG_HASH_SET_DATA(ctx, seed_len, seed_len);

	ctx->engine_is_instantiated = false;

	ctx->engine_magic = HASH_DRBG_INIT_MAGIC;

	ret = HASH_DRBG_OK;
err:
	return ret;
}

static drbg_error hash_drbg_init_with_strength(drbg_ctx *ctx,
					       uint32_t drbg_strength)
{
	drbg_error ret = HASH_DRBG_ERROR;
	hash_alg_type hash;
	int _ret;

	_ret = get_hash_from_strength(drbg_strength, &hash);
	if (_ret) {
		goto err;
	}

	ret = hash_drbg_init(ctx, hash);

err:
	return ret;
}

/****************************************************************/
/* External API */
drbg_error hash_drbg_get_lengths(drbg_options *options,
			         uint32_t *drbg_strength,
				 uint32_t *min_entropy_input_length,
				 uint32_t *max_entropy_input_length,
				 uint32_t *max_pers_string_length,
				 uint32_t *max_addin_length,
				 uint32_t *max_asked_length)
{
	drbg_error ret = HASH_DRBG_ERROR;
	drbg_ctx ctx;

	/* Honor options and then drbg_strength in this order */
	if(options != NULL){
		/* Perform "fake" init to recover the needed data */
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_HASH_OPTIONS_MAGIC) ||
		   (options->type != DRBG_HASH)){
			ret = HASH_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if((ret = hash_drbg_init(&ctx,
					 DRBG_HASH_OPTIONS_GET_DATA(options, hash_type)))
						!= HASH_DRBG_OK){
			goto err;
		}
	}
	else if(drbg_strength != NULL){
		/* Perform "fake" init to recover the needed data */
		if((ret = hash_drbg_init_with_strength(&ctx, (*drbg_strength)))
						 != HASH_DRBG_OK){
			goto err;
		}
	}
	else{
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Now sanity check the strength */
	if((drbg_strength != NULL) && (ctx.drbg_strength < (*drbg_strength))){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Set our values according to the asked data */
	if(drbg_strength != NULL){
		(*drbg_strength) = ctx.drbg_strength;
	}
	if(min_entropy_input_length != NULL){
		(*min_entropy_input_length) = ctx.min_entropy_input_length;
	}
	if(max_entropy_input_length != NULL){
		(*max_entropy_input_length) = ctx.max_entropy_input_length;
	}
	if(max_pers_string_length != NULL){
		(*max_pers_string_length) = ctx.max_pers_string_length;
	}
	if(max_addin_length != NULL){
		(*max_addin_length) = ctx.max_addin_length;
	}
	if(max_asked_length != NULL){
		(*max_asked_length) = ctx.max_asked_length;
	}

err:
	/* Cleanup local stack */
	memset(&ctx, 0, sizeof(ctx));

	return ret;
}

drbg_error hash_drbg_instantiate(drbg_ctx *ctx,
				      const unsigned char *entropy_input, uint32_t entropy_input_len,
				      const unsigned char *nonce, uint32_t nonce_len,
				      const unsigned char *pers_string, uint32_t pers_string_len,
				      uint32_t *asked_strength,
				      drbg_options *options)
{
	drbg_error ret = HASH_DRBG_ERROR;
	in_scatter_data sc[3] = { { .data = NULL, .data_len = 0 } };
	uint8_t zero = 0x00;
	uint32_t digest_size, seed_len;
	uint8_t *V, *C;

	/* HASH DRBG instantiation requires valid entropy_input and nonce */
	if((ctx == NULL) ||
	   (entropy_input == NULL) || (entropy_input_len == 0) ||
	   (nonce == NULL) || (nonce_len == 0)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* pers string can be empty or null, but not null with a non zero length */
	if((pers_string == NULL) && (pers_string_len != 0)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(options != NULL){
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_HASH_OPTIONS_MAGIC) ||
		   (options->type != DRBG_HASH)){
			ret = HASH_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if((ret = hash_drbg_init(ctx, DRBG_HASH_OPTIONS_GET_DATA(options, hash_type)))
						!= HASH_DRBG_OK){
			goto err;
		}
		if(asked_strength != NULL){
			/* Now check the strength */
			if(ctx->drbg_strength < (*asked_strength)){
				ret = HASH_DRBG_ILLEGAL_INPUT;
				goto err;
			}
		}
	}
	else{
		if(asked_strength == NULL){
			ret = HASH_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		/* No options, go to default init with the provided strength */
		if((ret = hash_drbg_init_with_strength(ctx, (*asked_strength))) != HASH_DRBG_OK){
			goto err;
		}
	}

	if(hash_drbg_check_initialized(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}

	if(asked_strength != NULL){
		(*asked_strength) = ctx->drbg_strength;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, &nonce_len,
				     &pers_string_len, NULL, NULL)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	seed_len    = DRBG_HASH_GET_DATA(ctx, seed_len);
	V           = DRBG_HASH_GET_DATA(ctx, V);
	C           = DRBG_HASH_GET_DATA(ctx, C);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(seed_len > HASH_DRBG_MAX_SEED_LEN){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	/* Hash_df our seed material with seed_material = entropy_input || nonce || pers_string */
	sc[0].data = entropy_input;
	sc[0].data_len = entropy_input_len;
	sc[1].data = nonce;
	sc[1].data_len = nonce_len;
	sc[2].data = pers_string;
	sc[2].data_len = pers_string_len;

	/* V = seed */
	if((ret = hash_drbg_hash_df(ctx, sc,
				    3, V, seed_len)) != HASH_DRBG_OK){
		goto err;
	}
	/* C = Hash_df ((0x00 || V), seedlen) */
	sc[0].data = &zero;
	sc[0].data_len = 1;
	sc[1].data = V;
	sc[1].data_len = seed_len;
	if((ret = hash_drbg_hash_df(ctx, sc,
				    2, C, seed_len)) != HASH_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	/* Tell that our instantiation is OK */
	ctx->type = DRBG_HASH;
	ctx->engine_is_instantiated = true;

	ret = HASH_DRBG_OK;

err:
	/* In case of error, uninit our context */
	if((ret != HASH_DRBG_OK) && (ctx != NULL)){
		hash_drbg_uninit(ctx);
	}
	return ret;
}

drbg_error hash_drbg_reseed(drbg_ctx *ctx,
				 const unsigned char *entropy_input, uint32_t entropy_input_len,
				 const unsigned char *addin, uint32_t addin_len)
{
	drbg_error ret = HASH_DRBG_ERROR;
	in_scatter_data sc[4] = { { .data = NULL, .data_len = 0 } };
	uint8_t temp[HASH_DRBG_MAX_DIGEST_OR_SEED_SIZE] = { 0 };
	uint8_t zero = 0x00, one = 0x01;
	uint32_t digest_size, seed_len;
	uint8_t *V, *C;

	if((ctx == NULL) || (entropy_input == NULL) || (entropy_input_len == 0)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* additional input can be empty or null, but not null with a non zero length */
	if((addin == NULL) && (addin_len != 0)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(hash_drbg_check_instantiated(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, NULL,
				     NULL, &addin_len, NULL)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	seed_len    = DRBG_HASH_GET_DATA(ctx, seed_len);
	V           = DRBG_HASH_GET_DATA(ctx, V);
	C           = DRBG_HASH_GET_DATA(ctx, C);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(seed_len > HASH_DRBG_MAX_SEED_LEN){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}

	/* Hash_df our seed material with seed_material = 0x01 || V || entropy_input || additional_input */
	sc[0].data = &one;
	sc[0].data_len = 1;
	sc[1].data = V;
	sc[1].data_len = seed_len;
	sc[2].data = entropy_input;
	sc[2].data_len = entropy_input_len;
	sc[3].data = addin;
	sc[3].data_len = addin_len;

	/* V = seed */
	if((ret = hash_drbg_hash_df(ctx, sc, 4, temp, seed_len)) != HASH_DRBG_OK){
		goto err;
	}
	memcpy(V, temp, seed_len);
	/* C = Hash_df ((0x00 || V), seedlen) */
	sc[0].data = &zero;
	sc[0].data_len = 1;
	sc[1].data = V;
	sc[1].data_len = seed_len;
	if((ret = hash_drbg_hash_df(ctx, sc,
				    2, C, seed_len)) != HASH_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	ret = HASH_DRBG_OK;
err:
	return ret;
}

drbg_error hash_drbg_generate(drbg_ctx *ctx,
			      const unsigned char *addin, uint32_t addin_len,
			      unsigned char *out, uint32_t out_len)
{
	drbg_error ret = HASH_DRBG_ERROR;
	in_scatter_data sc[3] = { { .data = NULL, .data_len = 0 } };
	uint8_t two = 0x02, three = 0x03;
	uint8_t H[HASH_DRBG_MAX_DIGEST_OR_SEED_SIZE] = { 0 };
	uint32_t digest_size, seed_len, offset = 0;
	uint8_t *V, *C;

	if(ctx == NULL){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if((addin == NULL) && (addin_len != 0)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(hash_drbg_check_instantiated(ctx) != HASH_DRBG_OK){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	digest_size = DRBG_HASH_GET_DATA(ctx, digest_size);
	seed_len    = DRBG_HASH_GET_DATA(ctx, seed_len);
	V           = DRBG_HASH_GET_DATA(ctx, V);
	C           = DRBG_HASH_GET_DATA(ctx, C);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}
	if(seed_len > HASH_DRBG_MAX_SEED_LEN){
		ret = HASH_DRBG_HASH_ERROR;
		goto err;
	}
	if(ctx->reseed_counter < 1){
		/* DRBG not seeded yet! */
		ret = HASH_DRBG_NON_INIT;
		goto err;
	}

	/* Sanity checks on input length */
	if(common_drbg_lengths_check(ctx, NULL, NULL,
				     NULL, &addin_len, &out_len)){
		ret = HASH_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(ctx->reseed_counter > ctx->reseed_interval){
		ret = HASH_DRBG_NEED_RESEED;
		goto err;
	}

	/* If (additional_input ≠ Null), then do */
	if((addin != NULL) && (addin_len != 0)){
		unsigned char w[HASH_DRBG_MAX_DIGEST_OR_SEED_SIZE] = { 0 };
		sc[0].data = &two;
		sc[0].data_len = 1;
		sc[1].data = V;
		sc[1].data_len = seed_len;
		sc[2].data = addin;
		sc[2].data_len = addin_len;
		/* w = Hash (0x02 || V || additional_input) */
		offset = 0;
		if(seed_len > digest_size){
			offset = (seed_len - digest_size);
			if((offset + digest_size) > sizeof(w)){
				ret = HASH_DRBG_HASH_ERROR;
				goto err;
			}
		}
		if((ret = hash_drbg_hash(ctx, sc, 3,
					 &w[offset], digest_size)) != HASH_DRBG_OK){
			goto err;
		}
		/* Truncate w if necessary */
		if(digest_size > seed_len){
			memcpy(w, &w[offset], seed_len);
		}
		/* V = (V + w) mod 2 seedlen */
		hash_drbg_integer_sum(V, w, V, seed_len);
	}

	/* (returned_bits) = Hashgen (requested_number_of_bits, V) */
	if((ret = hash_drbg_hashgen(ctx, out, out_len)) != HASH_DRBG_OK){
		goto err;
	}

	/* H = Hash (0x03 || V) */
	sc[0].data = &three;
	sc[0].data_len = 1;
	sc[1].data = V;
	sc[1].data_len = seed_len;
	offset = 0;
	if(seed_len > digest_size){
		offset = (seed_len - digest_size);
		if((offset + digest_size) > sizeof(H)){
			ret = HASH_DRBG_HASH_ERROR;
			goto err;
		}
	}
	if((ret = hash_drbg_hash(ctx, sc, 2, &H[offset], digest_size)) != HASH_DRBG_OK){
		goto err;
	}
	/* Truncate H if necessary */
	if(digest_size > seed_len){
		memcpy(H, &H[offset], seed_len);
	}
	/* V = (V + H + C + reseed_counter) mod 2 seedlen.
	 * We do that in 3 consecutive steps.
	 */
	/* First compute V = (V + H + C) mod 2 seedlen */
	hash_drbg_integer_sum(V, H, V, seed_len);
	hash_drbg_integer_sum(V, C, V, seed_len);
	/* Reuse H as temporary space to store our counter */
	memset(H, 0, seed_len);
	PUT_UINT32_BE(ctx->reseed_counter, H, (seed_len - 4));
	/* Then V = (V + reseed_counter) mod 2 seedlen */
	hash_drbg_integer_sum(V, H, V, seed_len);

	/* Update the reseed counter */
	ctx->reseed_counter++;

	ret = HASH_DRBG_OK;
err:
	return ret;
}

drbg_error hash_drbg_uninstantiate(drbg_ctx *ctx)
{
	drbg_error ret = HASH_DRBG_ERROR;
	uint8_t *V, *C;

	if(hash_drbg_uninit(ctx) != HASH_DRBG_OK){
		goto err;
	}

	V = DRBG_HASH_GET_DATA(ctx, V);
	C = DRBG_HASH_GET_DATA(ctx, C);

	/* Cleanup stuff inside our state */
	memset(V, 0x00, DRBG_HASH_V_SIZE);
	memset(C, 0x00, DRBG_HASH_C_SIZE);

	DRBG_HASH_SET_DATA(ctx, digest_size, 0);
	DRBG_HASH_SET_DATA(ctx, seed_len, 0);
	DRBG_HASH_SET_DATA(ctx, hash_type, HASH_UNKNOWN_HASH_ALG);

	common_drbg_ctx_uninit(ctx);

	ret = HASH_DRBG_OK;
err:
	return ret;
}

#else /* !WITH_HASH_DRBG */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HASH_DRBG */
