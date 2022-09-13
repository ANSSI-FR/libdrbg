/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_BC_AES

/* Top header for AES glue */
#include "aes_glue.h"

static unsigned int get_bit_len(enum aes_key_len key_len)
{
	switch (key_len) {
	case AES128:
		return 128;
	case AES192:
		return 192;
	case AES256:
		return 256;
	default:
		return 128;
	}
}

/* This is the main AES core dispatcher, useful for software versions and useful for handling modes */
static int aes_core(aes_context * aes_ctx,
					const unsigned char data_in[AES_BLOCK_SIZE],
					unsigned char data_out[AES_BLOCK_SIZE],
					enum aes_dir dir)
{
	int ret = -1;

	if (dir == AES_ENCRYPT) {
		if (aes_enc(&(aes_ctx->core_context), data_in, data_out)) {
			goto err;
		}
	} else if (dir == AES_DECRYPT) {
		if (aes_dec(&(aes_ctx->core_context), data_in, data_out)) {
			goto err;
		}
	} else {
		goto err;
	}

	ret = 0;
 err:
	return ret;
}

/** AES modes **/

/*** IV incrementation ****/
static void increment_iv(uint8_t IV[16])
{
	int j;
	unsigned char end = 0, dummy = 0;

	/* Avoid "unused variable" dummy */
	((void)dummy);

	/* Increment counter */
	for (j = AES_BLOCK_SIZE; j > 0; j--) {
		if(end == 0){
			if (++IV[j - 1] != 0) {
				end = 1;
			}
		}
		else{
			dummy++;
		}
	}
}

static void add_iv(uint8_t IV[16], unsigned int to_add)
{
	unsigned int i;
	for (i = 0; i < to_add; i++) {
		increment_iv(IV);
	}
}

static void increment_iv_ctx(aes_context * aes_ctx)
{
	increment_iv(aes_ctx->iv);
}

void add_iv_ctx(aes_context * aes_ctx, unsigned int to_add)
{
	add_iv(aes_ctx->iv, to_add);
}

int aes_mode(aes_context * aes_ctx, const unsigned char *data_in,
					unsigned char *data_out, unsigned int data_len)
{
	int ret = -1;

	switch (aes_ctx->mode) {
	case ECB:{
			unsigned int i;
			if ((data_len % AES_BLOCK_SIZE) != 0) {
				goto err;
			}
			for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
				if (aes_core
					(aes_ctx, data_in + (AES_BLOCK_SIZE * i),
					 data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
					goto err;
				}
			}
			break;
		}
	case CBC:{
			if ((data_len % AES_BLOCK_SIZE) != 0) {
				goto err;
			}
			if (aes_ctx->dir == AES_ENCRYPT) {
				unsigned int i, j;
				uint8_t iv_tmp[AES_BLOCK_SIZE];
				uint8_t tmp[AES_BLOCK_SIZE];
				memcpy(iv_tmp, aes_ctx->iv, sizeof(iv_tmp));
				for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
					for (j = 0; j < AES_BLOCK_SIZE; j++) {
						tmp[j] = data_in[(AES_BLOCK_SIZE * i) + j] ^ iv_tmp[j];
					}
					if (aes_core
						(aes_ctx, tmp, data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
						goto err;
					}
					memcpy(iv_tmp, data_out + (AES_BLOCK_SIZE * i),
						   sizeof(iv_tmp));
				}
			} else if (aes_ctx->dir == AES_DECRYPT) {
				unsigned int i, j;
				uint8_t iv_tmp[AES_BLOCK_SIZE];
				uint8_t tmp[AES_BLOCK_SIZE];
				memcpy(iv_tmp, aes_ctx->iv, sizeof(iv_tmp));
				for (i = 0; i < (data_len / AES_BLOCK_SIZE); i++) {
					memcpy(tmp, data_in + (AES_BLOCK_SIZE * i), sizeof(tmp));
					if (aes_core
						(aes_ctx, data_in + (AES_BLOCK_SIZE * i),
						 data_out + (AES_BLOCK_SIZE * i), aes_ctx->dir)) {
						goto err;
					}
					for (j = 0; j < AES_BLOCK_SIZE; j++) {
						data_out[(AES_BLOCK_SIZE * i) + j] ^= iv_tmp[j];
					}
					memcpy(iv_tmp, tmp, sizeof(iv_tmp));
				}
			} else {
				goto err;
			}
			break;
		}
	case CTR:{
			unsigned int i;
			unsigned int offset;
			/* Sanity check on the offset */
			if(aes_ctx->last_off > AES_BLOCK_SIZE){
				goto err;
			}
			offset = aes_ctx->last_off;
			for (i = 0; i < data_len; i++) {
				if (offset == 0) {
					if (aes_core
						(aes_ctx, aes_ctx->iv, aes_ctx->last_block_stream, AES_ENCRYPT)) {
						goto err;
					}
					increment_iv_ctx(aes_ctx);
				}
				data_out[i]  = data_in[i] ^ aes_ctx->last_block_stream[offset];
				/***/
				offset = (offset + 1) % AES_BLOCK_SIZE;
			}
			aes_ctx->last_off = offset;
			break;
		}
	default:
		goto err;
	}

	ret = 0;

err:
	return ret;
}

int aes_init(aes_context * aes_ctx, const unsigned char *key,
			 enum aes_key_len key_len, const unsigned char *iv,
			 enum aes_mode mode, enum aes_dir dir)
{
	int ret = -1;

	if (aes_ctx == NULL) {
		goto err;
	}
	aes_ctx->key_len = key_len;
	aes_ctx->mode = mode;
	aes_ctx->dir = dir;
	aes_ctx->last_off = 0;
	memset(aes_ctx->last_block_stream, 0, sizeof(aes_ctx->last_block_stream));

	if (iv != NULL) {
		memcpy(aes_ctx->iv, iv, AES_BLOCK_SIZE);
	} else {
		memset(aes_ctx->iv, 0, AES_BLOCK_SIZE);
	}
	switch (aes_ctx->mode) {
		case ECB:
		case CBC:
			if (dir == AES_ENCRYPT) {
				if (aes_setkey_enc
					(&(aes_ctx->core_context), key, get_bit_len(aes_ctx->key_len))) {
					goto err;
				}
			} else if (dir == AES_DECRYPT) {
				if (aes_setkey_dec
					(&(aes_ctx->core_context), key, get_bit_len(aes_ctx->key_len))) {
					goto err;
				}
			} else {
				goto err;
			}
			break;
			/* Stream mode only use encryption key schedule */
		case CTR:
			if (aes_setkey_enc
				(&(aes_ctx->core_context), key, get_bit_len(aes_ctx->key_len))) {
				goto err;
			}
			break;
		default:
			goto err;
	 }

	 ret = 0;
 err:
	 return ret;
}

int aes_exec(aes_context * aes_ctx, const unsigned char *data_in,
		unsigned char *data_out, unsigned int data_len)
{
	int ret = -1;

	if (aes_ctx == NULL) {
		goto err;
	}

	/* Use the software unmasked AES */
	if (aes_mode(aes_ctx, data_in, data_out, data_len)) {
		goto err;
	}

	ret = 0;

err:
	return ret;
}

#else /* !WITH_BC_AES */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_BC_AES */
