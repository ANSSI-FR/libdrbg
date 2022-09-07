/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HMAC_DRBG

#include "hmac_drbg.h"

/* Specific HMAC-DRBG data accessors */
#define DRBG_HMAC_GET_DATA(ctx, d)		(ctx)->data.hmac_data.d
#define DRBG_HMAC_SET_DATA(ctx, d, s)		(ctx)->data.hmac_data.d = (s)

#define DRBG_HMAC_OPTIONS_GET_DATA(o, d)        (o)->opt.hmac_options.d

/* HMAC-DRBG for PRNG.
 * Standardized by NIST SP 800-90A.
 */
static drbg_error hmac_drbg_check_initialized(drbg_ctx *ctx)
{
	drbg_error ret = HMAC_DRBG_ERROR;

	if(ctx == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctx->engine_magic != HMAC_DRBG_INIT_MAGIC){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}

	ret = HMAC_DRBG_OK;

err:
	return ret;
}

static drbg_error hmac_drbg_uninit(drbg_ctx *ctx)
{
	drbg_error ret = HMAC_DRBG_ERROR;

	if((ctx == NULL) || (ctx->engine_magic != HMAC_DRBG_INIT_MAGIC)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	ctx->engine_magic = 0x0;

	ret = HMAC_DRBG_OK;

err:
	return ret;
}

#define MAX_SCATTER_DATA 5

/* Internal HMAC helper */
static drbg_error hmac_drbg_hmac_internal(hmac_context *hmac_ctx,
				   const unsigned char *key, uint32_t key_len,
				   const in_scatter_data *data_bag_in, unsigned int data_bag_in_num,
				   unsigned char *output, uint32_t output_len,
				   hash_alg_type hash_type)
{
	drbg_error ret = HMAC_DRBG_ERROR;

	if(hmac_ctx == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if((data_bag_in == NULL) && (data_bag_in_num != 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(key != NULL){
		/* If the key is not NULL, initialize */
		/* Initialize our internal HMAC context with Key K */
		if(hmac_init(hmac_ctx, key, key_len, hash_type)){
			ret = HMAC_DRBG_HMAC_ERROR;
			goto err;
		}
	}

	/* Update */
	if(data_bag_in == NULL){
		/* Hashing an empty string */
		if(hmac_update(hmac_ctx, NULL, 0)){
			ret = HMAC_DRBG_HMAC_ERROR;
			goto err;
		}
	}
	else{
		unsigned int i;
		for(i = 0; i < data_bag_in_num; i++){
			if((data_bag_in[i].data == NULL) && (data_bag_in[i].data_len != 0)){
				ret = HMAC_DRBG_ILLEGAL_INPUT;
				goto err;
			}
			if(data_bag_in[i].data != NULL){
				if(hmac_update(hmac_ctx, data_bag_in[i].data, data_bag_in[i].data_len)){
					ret = HMAC_DRBG_HMAC_ERROR;
					goto err;
				}
			}
		}
	}

	/* If output is provided, finalize */
	if(output != NULL){
		uint8_t len = (output_len > 0xff) ? 0xff: (uint8_t)output_len;

		if(hmac_finalize(hmac_ctx, output, &len)){
			ret = HMAC_DRBG_HMAC_ERROR;
			goto err;
		}
	}

	ret = HMAC_DRBG_OK;

err:
	return ret;
}

/* The HMAC-DRBG update function */
static drbg_error hmac_drbg_update(drbg_ctx *ctx,
				   const in_scatter_data *data_bag_in, unsigned int data_bag_in_num)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	hmac_context hmac_ctx;
	unsigned int i;
	unsigned char tmp;
	unsigned int num_null = 0;
	in_scatter_data sc[MAX_SCATTER_DATA] = { { .data = NULL, .data_len = 0 } };
	uint32_t digest_size;
	hash_alg_type hash_type;
	uint8_t *V, *K;

	if(ctx == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(hmac_drbg_check_initialized(ctx) != HMAC_DRBG_OK){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}
	/* Access specific data */
	digest_size = DRBG_HMAC_GET_DATA(ctx, digest_size);
	hash_type   = DRBG_HMAC_GET_DATA(ctx, hash_type);
	V           = DRBG_HMAC_GET_DATA(ctx, V);
	K           = DRBG_HMAC_GET_DATA(ctx, K);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}
	if((data_bag_in == NULL) && (data_bag_in_num != 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if((MAX_SCATTER_DATA < 2) || (data_bag_in_num > (MAX_SCATTER_DATA - 2))){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	/* Compute K = H(K, V|0x00|data) */
	sc[0].data = V;
	sc[0].data_len = digest_size;
	tmp = 0x00;
	sc[1].data = &tmp;
	sc[1].data_len = sizeof(tmp);
	/* Copy the rest */
	for(i = 0; i < data_bag_in_num; i++){
		sc[2 + i] = data_bag_in[i];
	}
	if((ret = hmac_drbg_hmac_internal(&hmac_ctx, K, digest_size, sc,
					  (2 + data_bag_in_num), K,
					  digest_size,
					  hash_type)) != HMAC_DRBG_OK){
		goto err;
	}
	/* Compute V = H(K, V) */
	sc[0].data = V;
	sc[0].data_len = digest_size;
	if((ret = hmac_drbg_hmac_internal(&hmac_ctx, K, digest_size, sc,
					  1, V, digest_size,
					  hash_type)) != HMAC_DRBG_OK){
		goto err;
	}
	/* If data == NULL, then return (K, V) */
	for(i = 0; i < data_bag_in_num; i++){
		if((data_bag_in[i].data == NULL) || (data_bag_in[i].data_len == 0)){
			num_null++;
		}
	}
	if(num_null == data_bag_in_num){
		goto end;
	}
	/* Compute K = H(K, V|0x01|data) */
	sc[0].data = V;
	sc[0].data_len = digest_size;
	tmp = 0x01;
	sc[1].data = &tmp;
	sc[1].data_len = sizeof(tmp);
	/* Copy the rest */
	for(i = 0; i < data_bag_in_num; i++){
		sc[2 + i] = data_bag_in[i];
	}
	if((ret = hmac_drbg_hmac_internal(&hmac_ctx, K, digest_size, sc,
					  (2 + data_bag_in_num), K, digest_size,
					  hash_type)) != HMAC_DRBG_OK){
		goto err;
	}
	/* Compute V = H(K, V) */
	sc[0].data = V;
	sc[0].data_len = digest_size;
	if((ret = hmac_drbg_hmac_internal(&hmac_ctx, K, digest_size, sc,
					  1, V, digest_size,
					  hash_type)) != HMAC_DRBG_OK){
		goto err;
	}

end:
	ret = HMAC_DRBG_OK;
err:
	return ret;
}

/* return drbg strength in bits, digest size and block size in bytes */
static drbg_error hmac_drbg_get_strength(hash_alg_type hash_type,
					      uint32_t *drbg_strength,
					      uint32_t *digest_size,
					      uint32_t *block_size)
{
	uint8_t ds, bs;
	drbg_error ret = HMAC_DRBG_ERROR;

	if(drbg_strength == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(hash_get_hash_sizes(hash_type, &ds, &bs)){
		ret = HMAC_DRBG_ERROR;
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

	ret = HMAC_DRBG_OK;

err:
	return ret;
}

static drbg_error hmac_drbg_check_instantiated(drbg_ctx *ctx)
{
	drbg_error ret = HMAC_DRBG_NON_INIT;

	if((ret = hmac_drbg_check_initialized(ctx)) != HMAC_DRBG_OK){
		goto err;
	}
	if(ctx->engine_is_instantiated == false){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}
	/* Sanity check on the global DRBG type */
	if(ctx->type != DRBG_HMAC){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}

	ret = HMAC_DRBG_OK;

err:
	return ret;
}

static drbg_error hmac_drbg_init(drbg_ctx *ctx,
				 hash_alg_type hash_type)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	uint32_t digest_size;
	uint8_t *V, *K;

#ifdef STRICT_NIST_SP800_90A
	/* In "strict" NIST mode, we only support the approved algorithms in Table 2. */
	unsigned int i;
	uint8_t found = 0;

	for(i = 0; i < (sizeof(nist_supported_hashes) / sizeof(hash_alg_type)); i++){
		if((hash_type == nist_supported_hashes[i]) && (hash_type != HASH_UNKNOWN_HASH_ALG)){
			found = 1;
			break;
		}
	}
	if(found == 0){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}
#endif

	if(ctx == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(hash_type == HASH_UNKNOWN_HASH_ALG){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	DRBG_HMAC_SET_DATA(ctx, hash_type, hash_type);
	/* Compute the strength */
	if((ret = hmac_drbg_get_strength(hash_type, &(ctx->drbg_strength),
					 &digest_size, NULL)) != HMAC_DRBG_OK){
		goto err;
	}
	DRBG_HMAC_SET_DATA(ctx, digest_size, digest_size);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}

	V = DRBG_HMAC_GET_DATA(ctx, V);
	K = DRBG_HMAC_GET_DATA(ctx, K);
	memset(V, 0, DRBG_HMAC_V_SIZE);
	memset(K, 0, DRBG_HMAC_K_SIZE);
	ctx->reseed_counter = 0;
	/* Initialize stuff provided by NIST SP800-90A in table 2 */
	ctx->reseed_interval	      = HMAC_DRBG_MAX_RESEED_INTERVAL;
	ctx->min_entropy_input_length = (ctx->drbg_strength / 8);
	ctx->max_entropy_input_length = (HMAC_DRBG_MAX_ENTROPY_SIZE - 1);
	ctx->max_pers_string_length   = (HMAC_DRBG_MAX_PERS_STRING_SIZE - 1);
	ctx->max_addin_length	      = (HMAC_DRBG_MAX_ADDIN_SIZE - 1);

	/* Compute the max asked length */
	ctx->max_asked_length = HMAC_DRBG_MAX_ASKED_LENGTH;

	ctx->engine_is_instantiated = false;

	ctx->engine_magic = HMAC_DRBG_INIT_MAGIC;

	ret = HMAC_DRBG_OK;
err:
	return ret;
}

static drbg_error hmac_drbg_init_with_strength(drbg_ctx *ctx,
					       uint32_t drbg_strength)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	hash_alg_type hash;

	if (get_hash_from_strength(drbg_strength, &hash)) {
		goto err;
	}

	ret = hmac_drbg_init(ctx, hash);

err:
	return ret;
}

/****************************************************************/
/* External API */
drbg_error hmac_drbg_get_lengths(drbg_options *options,
				 uint32_t *drbg_strength,
				 uint32_t *min_entropy_input_length,
				 uint32_t *max_entropy_input_length,
				 uint32_t *max_pers_string_length,
				 uint32_t *max_addin_length,
				 uint32_t *max_asked_length)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	drbg_ctx ctx;

	/* Honor options and then drbg_strength in this order */
	if(options != NULL){
		/* Perform "fake" init to recover the needed data */
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_HMAC_OPTIONS_MAGIC) ||
		   (options->type != DRBG_HMAC)){
			ret = HMAC_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if((ret = hmac_drbg_init(&ctx, DRBG_HMAC_OPTIONS_GET_DATA(options, hash_type)))
							!= HMAC_DRBG_OK){
			goto err;
		}
	}
	else if(drbg_strength != NULL){
		/* Perform "fake" init to recover the needed data */
		if((ret = hmac_drbg_init_with_strength(&ctx, (*drbg_strength)))
							!= HMAC_DRBG_OK){
			goto err;
		}
	}
	else{
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if (drbg_strength != NULL) {
		/*
		 * Now sanity check the strength that was passed against the one
		 * used after init. This validates the coherency between options
		 * and passed strength if both were given
		 */
		if (ctx.drbg_strength < (*drbg_strength)) {
			ret = HMAC_DRBG_ILLEGAL_INPUT;
			goto err;
		}

		/* Now, we can return effective strength */
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

drbg_error hmac_drbg_instantiate(drbg_ctx *ctx,
				 const unsigned char *entropy_input, uint32_t entropy_input_len,
				 const unsigned char *nonce, uint32_t nonce_len,
				 const unsigned char *personalization_string, uint32_t personalization_string_len,
				 uint32_t *asked_strength,
				 drbg_options *options)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	in_scatter_data sc[3] = { { .data = NULL, .data_len = 0 } };
	uint32_t digest_size;
	uint8_t *V, *K;

	/* HMAC DRBG instantiation requires valid entropy_input and nonce */
	if((ctx == NULL) ||
	   (entropy_input == NULL) || (entropy_input_len == 0) ||
	   (nonce == NULL) || (nonce_len == 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* pers string can be empty or null, but not null with a non zero length */
	if((personalization_string == NULL) && (personalization_string_len != 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(options != NULL){
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_HMAC_OPTIONS_MAGIC) ||
		   (options->type != DRBG_HMAC)){
			ret = HMAC_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if((ret = hmac_drbg_init(ctx,
					 DRBG_HMAC_OPTIONS_GET_DATA(options, hash_type)))
						!= HMAC_DRBG_OK){
			goto err;
		}
		if(asked_strength != NULL){
			/* Now check the strength */
			if(ctx->drbg_strength < (*asked_strength)){
				ret = HMAC_DRBG_ILLEGAL_INPUT;
				goto err;
			}
		}
	}
	else{
		if(asked_strength == NULL){
			ret = HMAC_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		/* No options, go to default init with the provided strength */
		if((ret = hmac_drbg_init_with_strength(ctx, (*asked_strength))) != HMAC_DRBG_OK){
			goto err;
		}
	}

	if(hmac_drbg_check_initialized(ctx) != HMAC_DRBG_OK){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}

	if(asked_strength != NULL){
		(*asked_strength) = ctx->drbg_strength;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, &nonce_len,
				     &personalization_string_len, NULL, NULL)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	digest_size = DRBG_HMAC_GET_DATA(ctx, digest_size);
	V	    = DRBG_HMAC_GET_DATA(ctx, V);
	K	    = DRBG_HMAC_GET_DATA(ctx, K);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}

	/* Initialize K with 0x000 ... 00 */
	memset(K, 0x00, digest_size);
	/* Initialize V with 0x0101  ... 01 */
	memset(V, 0x01, digest_size);

	/*
	 * (K, V) = update(seed_material, K, V))
	 * with seed_material = entropy_input || nonce || personalization_string
	 */
	sc[0].data = entropy_input;
	sc[0].data_len = entropy_input_len;
	sc[1].data = nonce;
	sc[1].data_len = nonce_len;
	sc[2].data = personalization_string;
	sc[2].data_len = personalization_string_len;
	if((ret = hmac_drbg_update(ctx, sc, 3)) != HMAC_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	/* Tell that our instantiation is OK */
	ctx->type = DRBG_HMAC;
	ctx->engine_is_instantiated = true;

	ret = HMAC_DRBG_OK;
err:
	return ret;
}


drbg_error hmac_drbg_reseed(drbg_ctx *ctx,
			    const unsigned char *entropy_input, uint32_t entropy_input_len,
			    const unsigned char *addin, uint32_t addin_len)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	in_scatter_data sc[2] = { { .data = NULL, .data_len = 0 } };
	uint32_t digest_size;

	if((ctx == NULL) || (entropy_input == NULL) || (entropy_input_len == 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* additional input can be empty or null, but not null with a non zero length */
	if((addin == NULL) && (addin_len != 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(hmac_drbg_check_instantiated(ctx) != HMAC_DRBG_OK){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, NULL,
				     NULL, &addin_len, NULL)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	digest_size = DRBG_HMAC_GET_DATA(ctx, digest_size);
	if(digest_size > MAX_DIGEST_SIZE){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}

	/* (K, V) = update(seed_material, K, V))
	 * with seed_material = data | addin
	 */
	sc[0].data = entropy_input;
	sc[0].data_len = entropy_input_len;
	sc[1].data = addin;
	sc[1].data_len = addin_len;
	if((ret = hmac_drbg_update(ctx, sc, 2)) != HMAC_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	ret = HMAC_DRBG_OK;
err:
	return ret;
}

drbg_error hmac_drbg_generate(drbg_ctx *ctx,
			      const unsigned char *addin, uint32_t addin_len,
			      unsigned char *out, uint32_t out_len)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	hmac_context hmac_ctx;
	uint32_t generated = 0;
	in_scatter_data sc[1] = { { .data = NULL, .data_len = 0 } };
	uint32_t digest_size;
	hash_alg_type hash_type;
	uint8_t *V, *K;

	if(ctx == NULL){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	/*
	 * additional input string can be empty or null, but not null with a
	 * non zero length
	 */
	if((addin == NULL) && (addin_len != 0)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(hmac_drbg_check_instantiated(ctx) != HMAC_DRBG_OK){
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}
	/* Access specific data */
	digest_size = DRBG_HMAC_GET_DATA(ctx, digest_size);
	hash_type   = DRBG_HMAC_GET_DATA(ctx, hash_type);
	V	    = DRBG_HMAC_GET_DATA(ctx, V);
	K	    = DRBG_HMAC_GET_DATA(ctx, K);

	if(digest_size > MAX_DIGEST_SIZE){
		ret = HMAC_DRBG_HMAC_ERROR;
		goto err;
	}
	if(ctx->reseed_counter < 1){
		/* DRBG not seeded yet! */
		ret = HMAC_DRBG_NON_INIT;
		goto err;
	}
	/* Sanity checks on input length */
	if(common_drbg_lengths_check(ctx, NULL, NULL,
				     NULL, &addin_len, &out_len)){
		ret = HMAC_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(ctx->reseed_counter > ctx->reseed_interval){
		ret = HMAC_DRBG_NEED_RESEED;
		goto err;
	}

	/* (K, V) = update(addin, K, V) if addin != NULL */
	if((addin != NULL) && (addin_len != 0)){
		sc[0].data = addin;
		sc[0].data_len = addin_len;
		if((ret = hmac_drbg_update(ctx, sc, 1)) != HMAC_DRBG_OK){
			goto err;
		}
	}

	/* Generate he bitstream until we have enough data */
	while(generated < out_len){
		unsigned int size_to_copy;
		/* Compute V = H(K, V) */
		sc[0].data = V;
		sc[0].data_len = digest_size;
		if((ret = hmac_drbg_hmac_internal(&hmac_ctx, K, digest_size, sc,
						  1, V, digest_size,
						  hash_type)) != HMAC_DRBG_OK){
			goto err;
		}
		/* Copy V in output */
		size_to_copy = ((out_len - generated) < digest_size) ? (out_len - generated) : digest_size;
		memcpy((out + generated), V, size_to_copy);
		generated += digest_size;
	}

	/* (K, V) = update(addin, K, V) */
	sc[0].data = addin;
	sc[0].data_len = addin_len;
	if((ret = hmac_drbg_update(ctx, sc, 1)) != HMAC_DRBG_OK){
		goto err;
	}
	/* Update the reseed counter */
	ctx->reseed_counter++;

	ret = HMAC_DRBG_OK;
err:
	return ret;
}

drbg_error hmac_drbg_uninstantiate(drbg_ctx *ctx)
{
	drbg_error ret = HMAC_DRBG_ERROR;
	uint8_t *V, *K;

	if(hmac_drbg_uninit(ctx) != HMAC_DRBG_OK){
		goto err;
	}

	V = DRBG_HMAC_GET_DATA(ctx, V);
	K = DRBG_HMAC_GET_DATA(ctx, K);

	/* Cleanup stuff inside our state */
	memset(K, 0x00, DRBG_HMAC_K_SIZE);
	memset(V, 0x00, DRBG_HMAC_V_SIZE);

	DRBG_HMAC_SET_DATA(ctx, digest_size, 0);
	DRBG_HMAC_SET_DATA(ctx, hash_type, HASH_UNKNOWN_HASH_ALG);

	common_drbg_ctx_uninit(ctx);

	ret = HMAC_DRBG_OK;
err:
	return ret;
}


#else /* !WITH_HMAC_DRBG */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_HMAC_DRBG */
