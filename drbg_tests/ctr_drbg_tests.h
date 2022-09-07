/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __CTR_DRBG_TESTS_H__
#define __CTR_DRBG_TESTS_H__

#ifdef WITH_CTR_DRBG
#include "ctr_drbg.h"

typedef enum {
        CTR_INSTANTIATE     = 0,
        CTR_RESEED_EXPLICIT = 1,
        CTR_RESEED_PR       = 2,
        CTR_GENERATE        = 3
} ctr_dbrg_self_test_op;
typedef struct {
        ctr_dbrg_self_test_op op;
        const char *EntropyInput;
	uint32_t EntropyInputLen;
        const char *Nonce;
	uint32_t NonceLen;
        const char *PersonalizationString;
	uint32_t PersonalizationStringLen;
        const char *AdditionalInput;
	uint32_t AdditionalInputLen;
        const char *EntropyInputPR;
	uint32_t EntropyInputPRLen;
        const char *EntropyInputReseed;
	uint32_t EntropyInputReseedLen;
        const char *AdditionalInputReseed;
	uint32_t AdditionalInputReseedLen;
        /* Expected out */
        const char *Key;
        const char *V;
        uint32_t outlen;
        const char *out;
} ctr_dbrg_self_test_expected;
typedef struct {
        const char *name;
	block_cipher_type ctrtype;
        bool use_df;
	uint32_t ctr_len;
        bool prediction_resistance;
        unsigned int num_gen;
        const ctr_dbrg_self_test_expected *Expected;
} ctr_dbrg_self_test;

#include <stdio.h>
int do_ctr_dbrg_self_tests(const ctr_dbrg_self_test *all_tests[], unsigned int num_tests);
#endif

#endif /* __CTR_DRBG_TESTS_H__ */
