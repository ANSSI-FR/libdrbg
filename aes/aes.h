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

#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stddef.h>

/*
 * NOTE: with small memory footprint, we use the simple
 * AES that has low memory usage. Else, we use table based
 * AES that is more efficient but uses big tables.
 */
#ifdef SMALL_MEMORY_FOOTPRINT
#define SIMPLE_AES
#else
#define TABLE_AES
#endif

#define AES_BLOCK_SIZE  16

typedef struct
{
	uint32_t nr;            /* Number of rounds  */
#ifdef SIMPLE_AES
	uint8_t rk[240];      /* AES round keys    */
#endif
#ifdef  TABLE_AES
	uint32_t rk[64]; /* AES round keys  */
#endif
}
aes_core_context;

enum {
	AES_ENC = 0,
	AES_DEC = 1
};

enum aes_key_len {
    AES128 = 0,
    AES192 = 1,
    AES256 = 2
};

enum aes_mode {
    ECB = 0,
    CBC = 1,
    CTR = 2
};

enum aes_dir {
    AES_ENCRYPT = 0,
    AES_DECRYPT = 1
};

int aes_setkey_enc(aes_core_context *ctx, const uint8_t *key, uint32_t keybits);

int aes_setkey_dec(aes_core_context *ctx, const uint8_t *key, uint32_t keybits);

int aes_enc(aes_core_context *ctx, const uint8_t data_in[16], uint8_t data_out[16]);

int aes_dec(aes_core_context *ctx, const uint8_t data_in[16], uint8_t data_out[16]);


typedef struct {
    /* AES internal context (depends on the underlying representation) */
    aes_core_context core_context;
    /* For streaming modes */
    unsigned int last_off;
    uint8_t last_block_stream[AES_BLOCK_SIZE];
    /* IV */
    unsigned char iv[AES_BLOCK_SIZE];
    enum aes_key_len key_len;
    enum aes_mode mode;
    enum aes_dir dir;
} aes_context;


#endif /* __AES_H__ */

#endif
