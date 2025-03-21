/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "ctr_drbg_tests.h"
#include "drbg_tests/test_vectors/ctr_drbg_tests_cases.h"
#include "hmac_drbg_tests.h"
#include "drbg_tests/test_vectors/hmac_drbg_tests_cases.h"
#include "hash_drbg_tests.h"
#include "drbg_tests/test_vectors/hash_drbg_tests_cases.h"
#include "drbg.h"

static inline int self_tests(void)
{
	int ret = -1;

#ifdef WITH_HASH_DRBG
	if(do_hash_dbrg_self_tests(all_hash_tests, num_hash_tests)){
		goto err;
	}
#endif
#ifdef WITH_HMAC_DRBG
	if(do_hmac_dbrg_self_tests(all_hmac_tests, num_hmac_tests)){
		goto err;
	}
#endif
#ifdef WITH_CTR_DRBG
	if(do_ctr_dbrg_self_tests(all_ctr_tests, num_ctr_tests)){
		goto err;
	}
#endif
	ret = 0;

err:
	return ret;
}

int main(int argc, char *argv[])
{
	((void)argc);
	((void)argv);
	{
		drbg_ctx drbg;
		drbg_error ret;
		const unsigned char pers_string[] = "DRBG_PERS";
		unsigned char output[1024] = { 0 };
		unsigned char entropy[256] = { 0 };
		unsigned char nonce[256] = { 0 };
		uint32_t max_len = 0;
		drbg_options opt;
		uint32_t security_strength;

                (void)pers_string;
                (void)output;
                (void)entropy;
                (void)nonce;
                (void)max_len;
                (void)opt;
		(void)security_strength;
		(void)ret;
		(void)drbg;

#ifdef WITH_CTR_DRBG
#ifdef WITH_BC_TDEA
		/* Test the CTR DRBG abstraction */
		DRBG_CTR_OPTIONS_INIT(opt, CTR_DRBG_BC_TDEA, true, 5);
		security_strength = 100;
		ret = drbg_instantiate_with_user_entropy(&drbg, pers_string, sizeof(pers_string) - 1, entropy, sizeof(entropy), nonce, sizeof(nonce), &security_strength, true, DRBG_CTR, &opt);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("DRBG_CTR instantiated with TDEA, actual security strength = %u\n", security_strength);
		max_len = 0;
		ret = drbg_get_max_asked_length(&drbg, &max_len);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("drbg_get_max_asked_length: %u\n", max_len);
		ret = drbg_generate(&drbg, NULL, 0, output, (max_len < sizeof(output)) ? max_len : sizeof(output), false);
		if(ret != DRBG_OK){
			goto err;
		}
		hexdump("output:", (const char*)output, sizeof(output));
		ret = drbg_uninstantiate(&drbg);
		if(ret != DRBG_OK){
			goto err;
		}
#endif
#ifdef WITH_BC_AES
		/**/
		DRBG_CTR_OPTIONS_INIT(opt, CTR_DRBG_BC_AES256, true, 0);
		ret = drbg_instantiate_with_user_entropy(&drbg, pers_string, sizeof(pers_string) - 1, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, true, DRBG_CTR, &opt);
		if(ret != DRBG_OK){
			goto err;
		}
		ret = drbg_get_drbg_strength(&drbg, &security_strength);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("DRBG_CTR instantiated with AES256, actual security strength = %u\n", security_strength);
		max_len = 0;
		ret = drbg_get_max_asked_length(&drbg, &max_len);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("drbg_get_max_asked_length: %u\n", max_len);
		ret = drbg_generate(&drbg, NULL, 0, output, (max_len < sizeof(output)) ? max_len : sizeof(output), true);
		if(ret != DRBG_OK){
			goto err;
		}
		hexdump("output:", (const char*)output, sizeof(output));
#endif
#endif
#if defined(WITH_HASH_DRBG) && defined(WITH_HASH_RIPEMD160)
		/* Test the Hash DRBG abstraction */
		DRBG_HASH_OPTIONS_INIT(opt, HASH_RIPEMD160);
		security_strength = 128;
		ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1, &security_strength, true, DRBG_HASH, &opt);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("DRBG_HASH instantiated with RIPEMD160, actual security strength = %u\n", security_strength);
		ret = drbg_generate(&drbg, NULL, 0, output, sizeof(output), true);
		if(ret != DRBG_OK){
			goto err;
		}
		hexdump("output:", (const char*)output, sizeof(output));
#endif
#if defined(WITH_HMAC_DRBG) && defined(WITH_HASH_SHA1)
		/* Test the HMAC DRBG abstraction */
		DRBG_HMAC_OPTIONS_INIT(opt, HASH_SHA1);
		security_strength = 128;
		ret = drbg_instantiate_with_user_entropy(&drbg, pers_string, sizeof(pers_string) - 1, entropy, sizeof(entropy), nonce, sizeof(nonce), &security_strength, false, DRBG_HMAC, &opt);
		if(ret != DRBG_OK){
			goto err;
		}
		printf("DRBG_HMAC instantiated with SHA1, actual security strength = %u\n", security_strength);
		ret = drbg_generate(&drbg, NULL, 0, output, sizeof(output), false);
		if(ret != DRBG_OK){
			goto err;
		}
		hexdump("output:", (const char*)output, sizeof(output));
#endif
	}
	{
		/* Self tests of all our (CTR, Hash, HMAC)DRBGs */
		if(self_tests()){
			printf("Error: self-tests failure!\n");
			goto err;
		}
	}
	return 0;
err:
	return -1;
}
