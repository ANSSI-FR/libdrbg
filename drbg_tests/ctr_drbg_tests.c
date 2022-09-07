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

#include "ctr_drbg_tests.h"

static const char *get_op_name(ctr_dbrg_self_test_op op){
	switch(op){
		case CTR_GENERATE:
			return "CTR_GENERATE";
		case CTR_INSTANTIATE:
			return "CTR_INSTANTIATE";
		case CTR_RESEED_EXPLICIT:
			return "CTR_RESEED_EXPLICIT";
		case CTR_RESEED_PR:
			return "CTR_RESEED_PR";
		default:
			return "UNKNOWN_OP";
	}
}

#define MAX_OUT_SIZE 2048

int do_ctr_dbrg_self_tests(const ctr_dbrg_self_test *all_tests[], unsigned int num_tests){
	unsigned int i, j;
	drbg_ctx ctx_;
	drbg_ctx *ctx = &ctx_;
	drbg_options options;
	unsigned int num_tests_checked = 0;

	for(i = 0; i < num_tests; i++){
		bool use_df;
		uint32_t ctr_len;
		const char *name;
		block_cipher_type bc_type;

                /* Skip dummy tests */
                if(all_tests[i] == NULL){
                        continue;
                }

		use_df = all_tests[i]->use_df;
		ctr_len = all_tests[i]->ctr_len;
		name = all_tests[i]->name;
		bc_type = all_tests[i]->ctrtype;

		/* Initialize our options
		 * NOTE: ctr_len = 0 means default.
		 */
		DRBG_CTR_OPTIONS_INIT(options, bc_type, use_df, ctr_len);

		printf("\n\t=========== Testing %s\n", name);
		num_tests_checked++;
		/* Parse all our tests */
		for(j = 0; j < all_tests[i]->num_gen; j++){
		        ctr_dbrg_self_test_op op = all_tests[i]->Expected[j].op;
			const unsigned char *EntropyInput = (const unsigned char*)all_tests[i]->Expected[j].EntropyInput;
			uint32_t EntropyInputLen = all_tests[i]->Expected[j].EntropyInputLen;
			const unsigned char *Nonce = (const unsigned char*)all_tests[i]->Expected[j].Nonce;
			uint32_t NonceLen = all_tests[i]->Expected[j].NonceLen;
			const unsigned char *PersonalizationString = (const unsigned char*)all_tests[i]->Expected[j].PersonalizationString;
			uint32_t PersonalizationStringLen = all_tests[i]->Expected[j].PersonalizationStringLen;
			const unsigned char *AdditionalInput = (const unsigned char*)all_tests[i]->Expected[j].AdditionalInput;
			uint32_t AdditionalInputLen = all_tests[i]->Expected[j].AdditionalInputLen;
			const unsigned char *AdditionalInputReseed = (const unsigned char*)all_tests[i]->Expected[j].AdditionalInputReseed;
			uint32_t AdditionalInputReseedLen = all_tests[i]->Expected[j].AdditionalInputReseedLen;
			const unsigned char *EntropyInputPR = (const unsigned char*)all_tests[i]->Expected[j].EntropyInputPR;
			uint32_t EntropyInputPRLen = all_tests[i]->Expected[j].EntropyInputPRLen;
			const unsigned char *EntropyInputReseed = (const unsigned char*)all_tests[i]->Expected[j].EntropyInputReseed;
			uint32_t EntropyInputReseedLen = all_tests[i]->Expected[j].EntropyInputReseedLen;
			const unsigned char *V = (const unsigned char*)all_tests[i]->Expected[j].V;
			const unsigned char *Key = (const unsigned char*)all_tests[i]->Expected[j].Key;
			const unsigned char *expected_out = (const unsigned char*)all_tests[i]->Expected[j].out;
			unsigned char output[MAX_OUT_SIZE];
			uint32_t outlen = all_tests[i]->Expected[j].outlen;

			if(MAX_OUT_SIZE < outlen){
				/* Size overflow ... */
				printf("Output size overflow ...\n");
				goto err;
			}

			if(op == CTR_INSTANTIATE){
				/* Instantiate */
				printf("[CTR_INSTANTIATE]\n");
				if(ctr_drbg_instantiate(ctx, EntropyInput, EntropyInputLen, Nonce, NonceLen, PersonalizationString, PersonalizationStringLen, NULL, &options) != CTR_DRBG_OK){
					printf("Error in CTR_INSTANTIATE\n");
					goto err;
				}
			}
			else if(op == CTR_RESEED_EXPLICIT){
				printf("[RESEED (explicit)]\n");
				/* Explicitly call reseed */
				if(ctr_drbg_reseed(ctx, EntropyInputReseed, EntropyInputReseedLen, AdditionalInputReseed, AdditionalInputReseedLen) != CTR_DRBG_OK){
					printf("Error in CTR_RESEED_EXPLICIT\n");
					goto err;
				}
			}
			else if(op == CTR_RESEED_PR){
				printf("[RESEED (PR)]\n");
				/* Explicitly call reseed */
				if(ctr_drbg_reseed(ctx, EntropyInputPR, EntropyInputPRLen, AdditionalInput, AdditionalInputLen) != CTR_DRBG_OK){
					printf("Error in CTR_RESEED_PR\n");
					goto err;
				}
			}
			else if(op == CTR_GENERATE){
				printf("[CTR_GENERATE %u bytes]\n", outlen);
				if(ctr_drbg_generate(ctx, AdditionalInput, AdditionalInputLen, output, outlen) != CTR_DRBG_OK){
					printf("Error in CTR_GENERATE\n");
					goto err;
				}
			}
			else{
				/* Unknown operation */
				goto err;
			}

			/* Check internal state and output if necessary */
#ifdef CTR_DRBG_SELF_TESTS_VERBOSE
			hexdump("\tKey= ", (const char*)ctx->data.ctr_data.Key, ctx->data.ctr_data.key_len);
			hexdump("\tV  = ", (const char*)ctx->data.ctr_data.V, ctx->data.ctr_data.block_len);
#endif
			if((strlen((const char*)V) != 0) && (strlen((const char*)Key) != 0)){
				if((memcmp(ctx->data.ctr_data.V, V, ctx->data.ctr_data.block_len)) || (memcmp(ctx->data.ctr_data.Key, Key, ctx->data.ctr_data.key_len))){
					printf("Error for Key or V after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef CTR_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) Key= ", (const char*)Key, ctx->data.ctr_data.key_len);
					hexdump("\t(expected) V  = ", (const char*)V, ctx->data.ctr_data.block_len);
#endif
					goto err;
				}
			}
			if(strlen(((const char*)expected_out)) > 0){
#ifdef CTR_DRBG_SELF_TESTS_VERBOSE
				hexdump("\tout= ", (const char*)output, outlen);
#endif

				if(memcmp(output, expected_out, outlen)){
					printf("Error for output after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef CTR_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) out  = ", (const char*)expected_out, outlen);
#endif
					goto err;
				}
			}
		}
		/* Uninstantiate */
		ctr_drbg_uninstantiate(ctx);
	}
	printf("\n-----------------------------\n");
	printf("[+] All tests for CTR-DRBG are OK! :-)\n");
	printf("    (%u tests performed)\n", num_tests_checked);

	return 0;
err:
	return -1;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
