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

#include <string.h>
/* Top header for AES */
#include "aes.h"

void add_iv_ctx(aes_context * aes_ctx, unsigned int to_add);

int aes_mode(aes_context * aes_ctx, const unsigned char *data_in,
	     unsigned char *data_out, unsigned int data_len);

int aes_init(aes_context * aes_ctx, const unsigned char *key,
	     enum aes_key_len key_len, const unsigned char *iv,
	     enum aes_mode mode, enum aes_dir dir);

int aes_exec(aes_context * aes_ctx, const unsigned char *data_in,
	     unsigned char *data_out, unsigned int data_len);

#endif
