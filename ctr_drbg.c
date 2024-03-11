/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_CTR_DRBG

#include "ctr_drbg.h"

/* Specific CTR-DRBG data accessors */
#define DRBG_CTR_GET_DATA(ctx, d)		(ctx)->data.ctr_data.d
#define DRBG_CTR_SET_DATA(ctx, d, s)		(ctx)->data.ctr_data.d = (s)

#define DRBG_CTR_OPTIONS_GET_DATA(o, d)		(o)->opt.ctr_options.d

/* CTR-DRBG for PRNG.
 * Standardized by NIST SP 800-90A.
 */

static drbg_error ctr_drbg_check_initialized(drbg_ctx *ctx)
{
	drbg_error ret = CTR_DRBG_ERROR;

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctx->engine_magic != CTR_DRBG_INIT_MAGIC){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	ret = CTR_DRBG_OK;

err:
	return ret;
}

static drbg_error ctr_drbg_uninit(drbg_ctx *ctx)
{
	drbg_error ret = CTR_DRBG_ERROR;

	if((ctx == NULL) || (ctx->engine_magic != CTR_DRBG_INIT_MAGIC)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	ctx->engine_magic = 0x0;

	ret = CTR_DRBG_OK;

err:
	return ret;
}
static inline void ctr_drbg_integer_inc(const uint8_t *A, uint8_t *C,
					uint32_t size)
{
	integer_inc(A, C, size);

	return;
}

#ifdef WITH_BC_TDEA
/* Compute the TDEA keys with zero parity bits.
 * This allow to transform the 56 raw bits into 64 bits
 * (and hence 168 bits to 192 bits in the calling function).
 */
static void des_compute_key(const uint8_t *K, uint8_t *K_)
{
	unsigned int i;
	uint64_t k, k_;

	/* Extract our bits */
	k =   ( ((uint64_t) K[0]) << 48 )
	    | ( ((uint64_t) K[1]) << 40 )
	    | ( ((uint64_t) K[2]) << 32 )
	    | ( ((uint64_t) K[3]) << 24 )
	    | ( ((uint64_t) K[4]) << 16 )
	    | ( ((uint64_t) K[5]) <<  8 )
	    | ( ((uint64_t) K[6])	);

	k_ = 0;
	for(i = 0; i < 8; i++){
		k_ |= ((k & 0x7f) << 1) << (8*i);
		k = (k >> 7);
	}
	/* Store the new key and set the parity bits.
	 * NOTE: setting the parity bits is not necessary
	 * with our current underlying tdes implementation,
	 * we however leave it to remain compatible with
	 * other TDES APIs.
	 */
	PUT_UINT64_BE(k_, K_, 0);
	for(i = 0; i < 8; i++){
		K_[i] = odd_parity[K_[i]];
	}

	return;
}
#endif

/* The Block_Encrypt function */
static drbg_error ctr_drbg_block_encrypt(drbg_ctx *ctx,
					 const uint8_t *K, const uint8_t *B,
					 uint8_t *B_out)
{
	drbg_error ret = CTR_DRBG_ERROR;
	block_cipher_type bc_type;
	uint32_t key_len;

#if !defined(WITH_BC_TDEA) && !defined(WITH_BC_AES)
	/* Avoid unused variables */
	(void)ctx;
	(void)K;
	(void)B;
	(void)B_out;
#endif

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctr_drbg_check_initialized(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	/* Access specific data */
	bc_type = DRBG_CTR_GET_DATA(ctx, bc_type);
	key_len = DRBG_CTR_GET_DATA(ctx, key_len);

	switch(bc_type){
#ifdef WITH_BC_TDEA
		case CTR_DRBG_BC_TDEA:{
			des3_context des3_ctx;
			uint8_t K1[8], K2[8], K3[8];
			/* Compute and set TDEA keys parity bits */
			des_compute_key(&K[0],  K1);
			des_compute_key(&K[7],  K2);
			des_compute_key(&K[14], K3);
			if(des3_set_keys(&des3_ctx, K1, K2, K3, DES_ENCRYPTION)){
				ret = CTR_DRBG_ERROR;
				goto err;
			}
			if(des3(&des3_ctx, B, B_out)){
				ret = CTR_DRBG_ERROR;
				goto err;
			}
			break;
		}
#endif
#ifdef WITH_BC_AES
		case CTR_DRBG_BC_AES128:
		case CTR_DRBG_BC_AES192:
		case CTR_DRBG_BC_AES256:{
			aes_core_context aes_ctx;
			if(aes_setkey_enc(&aes_ctx, K, (8 * key_len))){
				ret = CTR_DRBG_ERROR;
				goto err;
			}
			if(aes_enc(&aes_ctx, B, B_out)){
				ret = CTR_DRBG_ERROR;
				goto err;
			}
			break;
		}
#endif
		default:{
			/* Avoid unused variable in conditional compilation */
			(void)key_len;
			ret = CTR_DRBG_ERROR;
			goto err;
		}
	}

	ret = CTR_DRBG_OK;
err:
	return ret;
}

/* The BCC function */
static drbg_error ctr_drbg_bcc(drbg_ctx *ctx,
				   const uint8_t *K,
				   const in_scatter_data *sc, unsigned int sc_num,
				   uint8_t *output_block)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint32_t data_len, i, block_len, cur_sc = 0, cur_sc_offset = 0, sc_remain;
	uint8_t block[CTR_DRBG_MAX_BLOCK_LEN] = { 0 };

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctr_drbg_check_initialized(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	/* Access specific data */
	block_len = DRBG_CTR_GET_DATA(ctx, block_len);

	/* Data input length must be exactly a multiple of block cipher block length */
	data_len = 0;
	for(i = 0; i < sc_num; i++){
		data_len += sc[i].data_len;
	}
	if((data_len % block_len) != 0){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Set chaining value to 0 */
	memset(output_block, 0, block_len);

	for (i = 0; i < (data_len / block_len); i++) {
		uint32_t needed, copied, local_offset = 0;
		unsigned int j;

		/* Copy data from scattered input to our block */
		while (local_offset < block_len) {
			sc_remain = sc[cur_sc].data_len - cur_sc_offset;
			if (!sc_remain) {
				/* switch to next entry in sc */
				cur_sc += 1;
				cur_sc_offset = 0;
				continue;
			}

			needed = (block_len - local_offset);
			copied = (needed < sc_remain) ? needed : sc_remain;
			memcpy(block+local_offset, sc[cur_sc].data+cur_sc_offset, copied);
			local_offset += copied;
			cur_sc_offset += copied;
		}

		for(j = 0; j < block_len; j++){
			output_block[j] ^= block[j];
		}

		if((ret = ctr_drbg_block_encrypt(ctx, K, output_block, output_block)) != CTR_DRBG_OK){
			goto err;
		}
	}

	ret = CTR_DRBG_OK;
err:
	return ret;

}

#define MAX_SCATTER_DATA 10
/*
 * The block cipher DF function. defined in section 10.3.2 of SP800-90Ar1.
 * input string is passed as scatter data and output size is expressed
 * in byte (not bits)
 */
static drbg_error ctr_drbg_block_cipher_df(drbg_ctx *ctx,
					       const in_scatter_data *sc, unsigned int sc_num,
					       uint8_t *output, uint32_t output_len)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint32_t block_len, key_len;
	uint32_t i, input_string_len, pad_len;
	in_scatter_data sc_data[MAX_SCATTER_DATA] = { { .data = NULL, .data_len = 0 } };

	uint8_t temp[CTR_DRBG_MAX_KEY_LEN + CTR_DRBG_MAX_BLOCK_LEN] = { 0 };
	uint8_t L[4] = { 0 }, N[4] = { 0 };
	uint8_t P[1] = { 0x80 };
	uint8_t K[CTR_DRBG_MAX_KEY_LEN] = { 0 };
	uint8_t IV[CTR_DRBG_MAX_BLOCK_LEN] = { 0 };
	uint8_t X[CTR_DRBG_MAX_BLOCK_LEN] = { 0 };

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctr_drbg_check_initialized(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}
	/* Sanity check on scatted data overflow */
	if((sc_num + 5) > MAX_SCATTER_DATA){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	block_len = DRBG_CTR_GET_DATA(ctx, block_len);
	key_len   = DRBG_CTR_GET_DATA(ctx, key_len);

	/* Sanity check */
	if(output_len > (512 / 8)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Compute input string length */
	input_string_len = 0;
	for(i = 0; i < sc_num; i++){
		input_string_len += sc[i].data_len;
	}

	/* Forge IV || S */
	PUT_UINT32_BE(input_string_len, L, 0);
	PUT_UINT32_BE(output_len, N, 0);

	sc_data[0].data = IV;
	sc_data[0].data_len = block_len;
	sc_data[1].data = L;
	sc_data[1].data_len = 4;
	sc_data[2].data = N;
	sc_data[2].data_len = 4;
	for(i = 0; i < sc_num; i++){
		sc_data[3 + i].data = sc[i].data;
		sc_data[3 + i].data_len = sc[i].data_len;
	}
	sc_data[3 + sc_num].data = P;
	sc_data[3 + sc_num].data_len = 1;
	/* Dealing with the padding */
	sc_data[4 + sc_num].data = X;
	pad_len = ((4 + 4 + input_string_len + 1) % block_len);
	pad_len = (pad_len == 0) ? 0 : (block_len - pad_len);
	sc_data[4 + sc_num].data_len = pad_len;

	for(i = 0; i < key_len; i++){
		K[i] = (uint8_t)i;
	}
	i = 0;
	while(i < (key_len + block_len)){
		PUT_UINT32_BE((i / block_len), IV, 0);
		if((ret = ctr_drbg_bcc(ctx, K, sc_data,
				       (5 + sc_num), &temp[i])) != CTR_DRBG_OK){
			goto err;
		}
		i += block_len;
	}
	memcpy(K, &temp[0], key_len);
	memcpy(X, &temp[key_len], block_len);

	memset(temp, 0, sizeof(temp));
	i = 0;
	while(i < output_len){
		if(i == 0){
			if((ret = ctr_drbg_block_encrypt(ctx, K, X,
							 &temp[0])) != CTR_DRBG_OK){
				goto err;
			}
		}
		else{
			if((ret = ctr_drbg_block_encrypt(ctx, K,
							 &temp[i - block_len],
							 &temp[i])) != CTR_DRBG_OK){
				goto err;
			}
		}
		i += block_len;
	}
	memcpy(output, temp, output_len);

	ret = CTR_DRBG_OK;
err:
	return ret;
}

static drbg_error ctr_drbg_update(drbg_ctx *ctx,
				  const unsigned char *provided_data, uint32_t provided_data_len)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint8_t temp[CTR_DRBG_MAX_SEED_LEN + CTR_DRBG_MAX_BLOCK_LEN] = { 0 };
	uint32_t temp_len;
	uint32_t key_len;
	uint32_t block_len;
	uint32_t ctr_len;
	uint32_t seed_len;
	unsigned int i;
	uint8_t *V, *Key;

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctr_drbg_check_initialized(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	/* Access specific data */
	block_len = DRBG_CTR_GET_DATA(ctx, block_len);
	key_len   = DRBG_CTR_GET_DATA(ctx, key_len);
	ctr_len   = DRBG_CTR_GET_DATA(ctx, ctr_len);
	seed_len  = DRBG_CTR_GET_DATA(ctx, seed_len);
	V         = DRBG_CTR_GET_DATA(ctx, V);
	Key       = DRBG_CTR_GET_DATA(ctx, Key);

	/* Sanity check on length */
	if(provided_data_len != seed_len){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	temp_len = 0;
	while(temp_len < seed_len){
		if(ctr_len < block_len){
			ctr_drbg_integer_inc(&(V[block_len - ctr_len]),
					     &(V[block_len - ctr_len]), ctr_len);
		}
		else{
			ctr_drbg_integer_inc(V, V, block_len);
		}
		if((ret = ctr_drbg_block_encrypt(ctx, Key, V,
						 &temp[temp_len])) != CTR_DRBG_OK){
			goto err;
		}
		temp_len += block_len;
	}
	for(i = 0; i < seed_len; i++){
		temp[i] ^= provided_data[i];
	}
	memcpy(Key, temp, key_len);
	memcpy(V, &temp[key_len], block_len);

	ret = CTR_DRBG_OK;
err:
	return ret;
}

static drbg_error ctr_drbg_check_instantiated(drbg_ctx *ctx)
{
	drbg_error ret = CTR_DRBG_NON_INIT;

	if((ret = ctr_drbg_check_initialized(ctx)) != CTR_DRBG_OK){
		goto err;
	}
	if(ctx->engine_is_instantiated == false){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}
	/* Sanity check on the global DRBG type */
	if(ctx->type != DRBG_CTR){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	ret = CTR_DRBG_OK;

err:
	return ret;
}

static drbg_error ctr_drbg_init(drbg_ctx *ctx,
				block_cipher_type bc_type,
				bool use_df, uint32_t ctr_len)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint32_t block_len, key_len, seed_len;
	uint8_t *V, *Key;

#if !defined(WITH_BC_TDEA) && !defined(WITH_BC_AES)
	/* Avoid unused variables */
	(void)V;
	(void)Key;
	(void)key_len;
	(void)seed_len;
	(void)use_df;
#endif

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/***********************************************/
	/* Handle the BC type */
	DRBG_CTR_SET_DATA(ctx, bc_type, bc_type);

	/* Initialize stuff provided by NIST SP800-90A in table 3 */
	/* Compute the security strength and other stuff */
	switch(bc_type){
#ifdef WITH_BC_TDEA
		case CTR_DRBG_BC_TDEA:{
			ctx->drbg_strength = 112;
			DRBG_CTR_SET_DATA(ctx, key_len, 21);
			DRBG_CTR_SET_DATA(ctx, block_len, 8);
			break;
		}
#endif
#ifdef WITH_BC_AES
		case CTR_DRBG_BC_AES128:{
			ctx->drbg_strength = 128;
			DRBG_CTR_SET_DATA(ctx, key_len, 16);
			DRBG_CTR_SET_DATA(ctx, block_len, 16);
			break;
		}
		case CTR_DRBG_BC_AES192:{
			ctx->drbg_strength = 192;
			DRBG_CTR_SET_DATA(ctx, key_len, 24);
			DRBG_CTR_SET_DATA(ctx, block_len, 16);
			break;
		}
		case CTR_DRBG_BC_AES256:{
			ctx->drbg_strength = 256;
			DRBG_CTR_SET_DATA(ctx, key_len, 32);
			DRBG_CTR_SET_DATA(ctx, block_len, 16);
			break;
		}
#endif
		default:{
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
	}

	key_len   = DRBG_CTR_GET_DATA(ctx, key_len);
	block_len = DRBG_CTR_GET_DATA(ctx, block_len);

	/***********************************************/
	/* Handle the ctr_len: 0 means default */
	if(ctr_len == 0){
		/* Default ctr_len is blocklen */
		block_len = DRBG_CTR_GET_DATA(ctx, block_len);
		DRBG_CTR_SET_DATA(ctx, ctr_len, block_len);
	}
	else{
		/* Sanity check that 4 <= ctr_len <= blocklen */
		if((ctr_len < 4) || (ctr_len > block_len)){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		DRBG_CTR_SET_DATA(ctx, ctr_len, ctr_len);
	}

	/***********************************************/
	/* Handle the max_asked_length */
	switch(bc_type){
#ifdef WITH_BC_TDEA
		case CTR_DRBG_BC_TDEA:{
			ctx->max_asked_length =
				CTR_DRBG_MAX_ASKED_LENGTH_TDEA(DRBG_CTR_GET_DATA(ctx, ctr_len));
			break;
		}
#endif
#ifdef WITH_BC_AES
		case CTR_DRBG_BC_AES128:
		case CTR_DRBG_BC_AES192:
		case CTR_DRBG_BC_AES256:{
			ctx->max_asked_length =
				CTR_DRBG_MAX_ASKED_LENGTH_AES(DRBG_CTR_GET_DATA(ctx, ctr_len));
			break;
		}
#endif
		default:{
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
	}

#if defined(WITH_BC_AES) || defined(WITH_BC_TDEA)
	/***********************************************/
	/* Handle seed_len
	 * seedlen = outlen + keylen
	 */
	seed_len = (block_len + key_len);
	DRBG_CTR_SET_DATA(ctx, seed_len, seed_len);
	switch(bc_type){
#ifdef WITH_BC_TDEA
		case CTR_DRBG_BC_TDEA:{
			ctx->reseed_interval = CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_TDEA;
			break;
		}
#endif
#ifdef WITH_BC_AES
		case CTR_DRBG_BC_AES128:
		case CTR_DRBG_BC_AES192:
		case CTR_DRBG_BC_AES256:{
			ctx->reseed_interval = CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_AES;
			break;
		}
#endif
		default:{
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
	}

	/***********************************************/
	/* Handle the DF option */
	DRBG_CTR_SET_DATA(ctx, use_df, use_df);
	/* Adapt stuff in the context */
	if(use_df == true){
		/* Values with DF */
		ctx->min_entropy_input_length = (ctx->drbg_strength / 8);
		ctx->max_entropy_input_length = (CTR_DRBG_MAX_ENTROPY_SIZE - 1);
		ctx->max_pers_string_length   = (CTR_DRBG_MAX_PERS_STRING_SIZE - 1);
		ctx->max_addin_length         = (CTR_DRBG_MAX_ADDIN_SIZE - 1);
	}
	else{
		/* Values with no DF */
		ctx->min_entropy_input_length = ctx->max_entropy_input_length = seed_len;
		ctx->max_pers_string_length = ctx->max_addin_length = seed_len;
	}

	Key = DRBG_CTR_GET_DATA(ctx, Key);
	V   = DRBG_CTR_GET_DATA(ctx, V);
	/* Zeroize values */
	memset(Key, 0, DRBG_CTR_KEY_SIZE);
	memset(V, 0, DRBG_CTR_V_SIZE);
	ctx->reseed_counter = 0;

	ctx->engine_is_instantiated = false;

	ctx->engine_magic = CTR_DRBG_INIT_MAGIC;

	ret = CTR_DRBG_OK;
#endif
err:
	return ret;
}

static drbg_error ctr_drbg_init_with_strength(drbg_ctx *ctx,
					      uint32_t drbg_strength)
{
	drbg_error ret = CTR_DRBG_ERROR;
	block_cipher_type bc_type = CTR_DRBG_BC_NONE;

#if !defined(WITH_BC_TDEA) && !defined(WITH_BC_AES)
	/* Avoid unused variables */
	(void)ctx;
	(void)drbg_strength;
	(void)bc_type;
#endif

#ifdef WITH_BC_TDEA
	if(drbg_strength <= 112){
		bc_type = CTR_DRBG_BC_TDEA;
	}
	else
#endif
#ifdef WITH_BC_AES
	if(drbg_strength <= 128){
		bc_type = CTR_DRBG_BC_AES128;
	}
	else if(drbg_strength <= 192){
		bc_type = CTR_DRBG_BC_AES192;
	}
	else if(drbg_strength <= 256){
		bc_type = CTR_DRBG_BC_AES256;
	}
	else
#endif
	{
		ret = CTR_DRBG_ERROR;
		goto err;
	}

#if defined(WITH_BC_AES) || defined(WITH_BC_TDEA)
	ret = ctr_drbg_init(ctx, bc_type, false, 0);
#endif
err:
	return ret;
}

/****************************************************************/
/* External API */
drbg_error ctr_drbg_get_lengths(drbg_options *options,
				uint32_t *drbg_strength,
				uint32_t *min_entropy_input_length,
				uint32_t *max_entropy_input_length,
				uint32_t *max_pers_string_length,
				uint32_t *max_addin_length,
				uint32_t *max_asked_length)
{
	drbg_error ret = CTR_DRBG_ERROR;
	drbg_ctx ctx;

	/* Honor options and then drbg_strength in this order */
	if(options != NULL){
		/* Perform "fake" init to recover the needed data */
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_CTR_OPTIONS_MAGIC) ||
		   (options->type != DRBG_CTR)){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if((ret = ctr_drbg_init(&ctx, DRBG_CTR_OPTIONS_GET_DATA(options, bc_type),
					DRBG_CTR_OPTIONS_GET_DATA(options, use_df), DRBG_CTR_OPTIONS_GET_DATA(options, ctr_len))) != CTR_DRBG_OK){
			goto err;
		}
	}
	else if(drbg_strength != NULL){
		/* Perform "fake" init to recover the needed data */
		if((ret = ctr_drbg_init_with_strength(&ctx, (*drbg_strength))) != CTR_DRBG_OK){
			goto err;
		}
	}
	else{
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Now sanity check the strength */
	if((drbg_strength != NULL) && (ctx.drbg_strength < (*drbg_strength))){
		ret = CTR_DRBG_ILLEGAL_INPUT;
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

drbg_error ctr_drbg_instantiate(drbg_ctx *ctx,
				const unsigned char *entropy_input, uint32_t entropy_input_len,
				const unsigned char *nonce, uint32_t nonce_len,
				const unsigned char *pers_string, uint32_t pers_string_len,
				uint32_t *asked_strength,
				drbg_options *options)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint8_t seed_material[CTR_DRBG_MAX_SEED_LEN] = { 0 };
	uint32_t seed_len;
	bool use_df;
	uint8_t *V, *Key;

	/* CTR DRBG instantiation requires valid entropy_input */
	if((ctx == NULL) || (entropy_input == NULL) || (entropy_input_len == 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* pers string can be empty or null, but not null with a non zero length */
	if((pers_string == NULL) && (pers_string_len != 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/*
	 * Unlike other DRBG (HMAC, HASH), CTR DRBG is specific regarding nonce:
	 * when DF is used, nonce is required; when DF is not used, nonce is not
	 * even considered. Here, we only check user does not pass a NULL pointer
	 * with a non zero length. Additional checks will be done later in the
	 * function when dealing with use_df flag.
	 */
	if((nonce == NULL) && (nonce_len != 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(options != NULL){
		/* If we have options, sanity check them and init with options */
		if((options->magic != DRBG_CTR_OPTIONS_MAGIC) ||
		   (options->type != DRBG_CTR)){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		/* Initialize with the options */
		if((ret = ctr_drbg_init(ctx, DRBG_CTR_OPTIONS_GET_DATA(options, bc_type),
					DRBG_CTR_OPTIONS_GET_DATA(options, use_df), DRBG_CTR_OPTIONS_GET_DATA(options, ctr_len))) != CTR_DRBG_OK){
			goto err;
		}
		if(asked_strength != NULL){
			/* Now check the strength */
			if(ctx->drbg_strength < (*asked_strength)){
				ret = CTR_DRBG_ILLEGAL_INPUT;
				goto err;
			}
		}
	}
	else{
		if(asked_strength == NULL){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		/* No options, go to default init with the provided strength */
		if((ret = ctr_drbg_init_with_strength(ctx, (*asked_strength))) != CTR_DRBG_OK){
			goto err;
		}
	}

	if(ctr_drbg_check_initialized(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	if(asked_strength != NULL){
		(*asked_strength) = ctx->drbg_strength;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, &nonce_len,
				     &pers_string_len, NULL, NULL)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	seed_len  = DRBG_CTR_GET_DATA(ctx, seed_len);
	use_df    = DRBG_CTR_GET_DATA(ctx, use_df);
	V         = DRBG_CTR_GET_DATA(ctx, V);
	Key       = DRBG_CTR_GET_DATA(ctx, Key);

	/* Sanity check */
	if(seed_len > CTR_DRBG_MAX_SEED_LEN){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(use_df == false){
		unsigned int i;
		uint32_t nonce_to_copy, remain;
		/** No DF case **/
		if(entropy_input_len != seed_len){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if(pers_string_len > seed_len){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}

		/*
		 * In No DF case, Nonce is not used by the standard. If user
		 * wants to use the nonce, it should concatenate it to the
		 * pers string. Note that we do not return an error if nonce
		 * was passed by the user and not used here.
		 */
		if(pers_string != NULL){
			/* Zero pad the pers_string to seed_len */
			memcpy(seed_material, pers_string, pers_string_len);
		}
		/*
		 * NOTE: when no DF is used, the nonce is optional for CTR-DBG. In this case,
		 * if the user provides a nonce, we copy as much as possible of it instead of losing
		 * it (if there is enough room in seed_material: this is useful fresh entropy).
		 */
		remain = (seed_len - pers_string_len);
		if((nonce != NULL) && (nonce_len != 0) && (remain > 0)){
			/* Add the maximum of input nonce */
			nonce_to_copy = (nonce_len < remain) ? nonce_len : remain;
			memcpy(&seed_material[pers_string_len], nonce, nonce_to_copy);
		}
		for(i = 0; i < seed_len; i++){
			seed_material[i] ^= entropy_input[i];
		}
	}
	else{
		/** DF case **/
		in_scatter_data sc[3] = { { .data = NULL, .data_len = 0 } };

		/* In DF case, nonce cannot be null/empty. */
		if ((nonce == NULL) || (nonce_len == 0)){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}

		sc[0].data = entropy_input;
		sc[0].data_len = entropy_input_len;
		sc[1].data = nonce;
		sc[1].data_len = nonce_len;
		sc[2].data = pers_string;
		sc[2].data_len = pers_string_len;

		/* Apply df */
		if((ret = ctr_drbg_block_cipher_df(ctx, sc, 3, seed_material, seed_len)) != CTR_DRBG_OK){
			goto err;
		}
	}

	memset(Key, 0, DRBG_CTR_KEY_SIZE);
	memset(V, 0, DRBG_CTR_V_SIZE);
	if((ret = ctr_drbg_update(ctx, seed_material, seed_len)) != CTR_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	/* Tell that our instantiation is OK */
	ctx->type = DRBG_CTR;
	ctx->engine_is_instantiated = true;

	ret = CTR_DRBG_OK;
err:
	return ret;
}

drbg_error ctr_drbg_reseed(drbg_ctx *ctx,
			   const unsigned char *entropy_input, uint32_t entropy_input_len,
			   const unsigned char *addin, uint32_t addin_len)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint8_t seed_material[CTR_DRBG_MAX_SEED_LEN] = { 0 };
	uint32_t seed_len;
	bool use_df;

	if((ctx == NULL) || (entropy_input == NULL) || (entropy_input_len == 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* additional input can be empty or null, but not null with a non zero length */
	if((addin == NULL) && (addin_len != 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(ctr_drbg_check_instantiated(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, &entropy_input_len, NULL,
				     NULL, &addin_len, NULL)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	seed_len = DRBG_CTR_GET_DATA(ctx, seed_len);
	use_df   = DRBG_CTR_GET_DATA(ctx, use_df);

	/* Sanity check */
	if(seed_len > CTR_DRBG_MAX_SEED_LEN){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(use_df == false){
		unsigned int i;
		/** No DF case **/
		if(entropy_input_len != seed_len){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if(addin_len > seed_len){
			ret = CTR_DRBG_ILLEGAL_INPUT;
			goto err;
		}
		if(addin != NULL){
			memcpy(seed_material, addin, addin_len);
		}
		for(i = 0; i < seed_len; i++){
			seed_material[i] ^= entropy_input[i];
		}
	}
	else{
		/** DF case **/
		in_scatter_data sc[2] = { { .data = NULL, .data_len = 0 } };
		sc[0].data = entropy_input;
		sc[0].data_len = entropy_input_len;
		sc[1].data = addin;
		sc[1].data_len = addin_len;

		/* Apply df */
		if((ret = ctr_drbg_block_cipher_df(ctx, sc, 2, seed_material, seed_len)) != CTR_DRBG_OK){
			goto err;
		}
	}

	if((ret = ctr_drbg_update(ctx, seed_material, seed_len)) != CTR_DRBG_OK){
		goto err;
	}

	/* Initialize reseed counter with 1 */
	ctx->reseed_counter = 1;

	ret = CTR_DRBG_OK;
err:
	return ret;
}

drbg_error ctr_drbg_generate(drbg_ctx *ctx,
			     const unsigned char *addin, uint32_t addin_len,
			     unsigned char *out, uint32_t out_len)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint8_t additional_input[CTR_DRBG_MAX_SEED_LEN] = { 0 };
	uint32_t seed_len, ctr_len, block_len;
	uint32_t i;
	bool use_df;
	uint8_t *V, *Key;

	if(ctx == NULL){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/*
	 * additional input string can be empty or null, but not null with a
	 * non zero length
	 */
	if((addin == NULL) && (addin_len != 0)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if(ctr_drbg_check_instantiated(ctx) != CTR_DRBG_OK){
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	/* Sanity checks on input lengths */
	if(common_drbg_lengths_check(ctx, NULL, NULL,
				     NULL, &addin_len, &out_len)){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	/* Access specific data */
	seed_len  = DRBG_CTR_GET_DATA(ctx, seed_len);
	ctr_len   = DRBG_CTR_GET_DATA(ctx, ctr_len);
	block_len = DRBG_CTR_GET_DATA(ctx, block_len);
	use_df    = DRBG_CTR_GET_DATA(ctx, use_df);
	V         = DRBG_CTR_GET_DATA(ctx, V);
	Key       = DRBG_CTR_GET_DATA(ctx, Key);

	if(ctx->reseed_counter < 1){
		/* DRBG not seeded yet! */
		ret = CTR_DRBG_NON_INIT;
		goto err;
	}

	if(ctx->reseed_counter > ctx->reseed_interval){
		ret = CTR_DRBG_NEED_RESEED;
		goto err;
	}

	/* Sanity check */
	if(seed_len > CTR_DRBG_MAX_SEED_LEN){
		ret = CTR_DRBG_ILLEGAL_INPUT;
		goto err;
	}

	if((addin != NULL) && (addin_len != 0)){
		if(use_df == false){
			/** No DF case **/
			if(addin_len > seed_len){
				ret = CTR_DRBG_ILLEGAL_INPUT;
				goto err;
			}
			memcpy(additional_input, addin, addin_len);
		}
		else{
			/** DF case **/
			in_scatter_data sc[1] = { { .data = NULL, .data_len = 0 } };
			sc[0].data = addin;
			sc[0].data_len = addin_len;

			/* Apply df */
			if((ret = ctr_drbg_block_cipher_df(ctx, sc, 1, additional_input, seed_len)) != CTR_DRBG_OK){
				goto err;
			}
		}
		if((ret = ctr_drbg_update(ctx, additional_input, seed_len)) != CTR_DRBG_OK){
			goto err;
		}
	}

	i = 0;
	while(i < out_len){
		uint8_t out_block[CTR_DRBG_MAX_BLOCK_LEN];
		uint32_t to_copy;
		if(ctr_len < block_len){
			ctr_drbg_integer_inc(&(V[block_len - ctr_len]), &(V[block_len - ctr_len]), ctr_len);
		}
		else{
			ctr_drbg_integer_inc(V, V, block_len);
		}
		if((ret = ctr_drbg_block_encrypt(ctx, Key, V, out_block)) != CTR_DRBG_OK){
			goto err;
		}
		to_copy = ((out_len - i) < block_len) ? (out_len - i) : block_len;
		memcpy(&out[i], out_block, to_copy);
		i += block_len;
	}

	if((ret = ctr_drbg_update(ctx, additional_input, seed_len)) != CTR_DRBG_OK){
		goto err;
	}

        /* Update the reseed counter */
        ctx->reseed_counter++;

	ret = CTR_DRBG_OK;
err:
	return ret;
}

drbg_error ctr_drbg_uninstantiate(drbg_ctx *ctx)
{
	drbg_error ret = CTR_DRBG_ERROR;
	uint8_t *V, *Key;

	if(ctr_drbg_uninit(ctx) != CTR_DRBG_OK){
		goto err;
	}

	V         = DRBG_CTR_GET_DATA(ctx, V);
	Key       = DRBG_CTR_GET_DATA(ctx, Key);

	/* Cleanup stuff inside our state */
	memset(Key, 0x00, DRBG_CTR_KEY_SIZE);
	memset(V, 0x00, DRBG_CTR_V_SIZE);

	DRBG_CTR_SET_DATA(ctx, key_len, 0);
	DRBG_CTR_SET_DATA(ctx, block_len, 0);
	DRBG_CTR_SET_DATA(ctx, ctr_len, 0);
	DRBG_CTR_SET_DATA(ctx, seed_len, 0);
	DRBG_CTR_SET_DATA(ctx, use_df, false);

	common_drbg_ctx_uninit(ctx);

	ret = CTR_DRBG_OK;
err:
	return ret;
}

#else /* !WITH_CTR_DRBG */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_CTR_DRBG */
