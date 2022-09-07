/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "entropy.h"

#ifdef WITH_TEST_ENTROPY_SOURCE
/* We provide some default entropy sources for testing if explicitly
 * asked to.
 */


/****************************************************************************/
/* Unix and compatible case (including macOS) */
#if (defined(__unix__) || defined(__APPLE__))
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Copy file content to buffer. Return 0 on success, i.e. if the request
 * size has been read and copied to buffer and -1 otherwise.
 */
static int fimport(uint8_t *buf, uint32_t buflen, const char *path)
{
	uint32_t rem = buflen, copied = 0;
	ssize_t ret;
	int fd;

	if ((buf == NULL) || (path == NULL)) {
		ret = -1;
		goto err;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("Unable to open input file %s\n", path);
		ret = -1;
		goto err;
	}

	while (rem) {
		ret = (int)read(fd, buf + copied, rem);
		if (ret <= 0) {
			break;
		} else {
			rem = (uint32_t)(rem - ret);
			copied = (uint32_t)(copied + ret);
		}
	}

	if (close(fd)) {
		printf("Unable to close input file %s\n", path);
		ret = -1;
		goto err;
	}

	ret = (copied == buflen) ? 0 : -1;

err:
	return (int)ret;
}

static int _get_entropy_input_from_os(uint8_t *buf, uint32_t len)
{
	int ret;

	ret = fimport(buf, len, "/dev/random");

	return ret;
}

/****************************************************************************/
#elif defined(__WIN32__)
#include <windows.h>
#include <wincrypt.h>

static int _get_entropy_input_from_os(uint8_t *buf, uint32_t len)
{
	int ret = -1;
	HCRYPTPROV hCryptProv = 0;

	if (CryptAcquireContext(&hCryptProv, NULL, NULL,
				PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		goto err;
	}

	if (CryptGenRandom(hCryptProv, len, buf) == FALSE) {
		CryptReleaseContext(hCryptProv, 0);
		goto err;
	}

	CryptReleaseContext(hCryptProv, 0);

	ret = 0;

err:
	return ret;
}
#else
#error "Sorry, unrecognized platform for WITH_TEST_ENTROPY_SOURCE! Only UNIX and Windows environments are supported"
#endif

#define ENTROPY_BUFF_LEN 1024

/* The entropy */
typedef struct {
	uint8_t entropy_buff[ENTROPY_BUFF_LEN];
	uint32_t entropy_buff_pos;
	uint32_t entropy_buff_len;
} entropy_pool;

static bool curr_entropy_pool_init = false;
static entropy_pool curr_entropy_pool;

int get_entropy_input(uint8_t **buf, uint32_t len, bool prediction_resistance)
{
	int ret = -1;

	/* Avoid unused parameter warnings */
	(void)prediction_resistance;

	if(curr_entropy_pool_init == false){
		/* Initialize our entropy pool */
		memset(curr_entropy_pool.entropy_buff, 0, sizeof(curr_entropy_pool.entropy_buff));
		curr_entropy_pool.entropy_buff_pos = curr_entropy_pool.entropy_buff_len = 0;

		curr_entropy_pool_init = true;
	}

	/* Sanity check */
	if(buf == NULL){
		goto err;
	}

	(*buf) = NULL;

	/* If we ask for more than the size of our entropy pool, return an error ... */
	if(len > sizeof(curr_entropy_pool.entropy_buff)){
		goto err;
	}
	else if(len <= curr_entropy_pool.entropy_buff_len){
		(*buf) = (curr_entropy_pool.entropy_buff + curr_entropy_pool.entropy_buff_pos);
		/* Remove the consumed data */
		curr_entropy_pool.entropy_buff_pos += len;
		curr_entropy_pool.entropy_buff_len -= len;
	}
	else{
		/* We do not have enough remaining data, reset and ask for maximum */
		ret = _get_entropy_input_from_os(curr_entropy_pool.entropy_buff, sizeof(curr_entropy_pool.entropy_buff));
		if(ret){
			goto err;
		}
		curr_entropy_pool.entropy_buff_pos = 0;
		curr_entropy_pool.entropy_buff_len = sizeof(curr_entropy_pool.entropy_buff);
		(*buf) = curr_entropy_pool.entropy_buff;
	}

	/* Sanity checks */
	if(curr_entropy_pool.entropy_buff_pos > sizeof(curr_entropy_pool.entropy_buff)){
		goto err;
	}
	if(curr_entropy_pool.entropy_buff_len > sizeof(curr_entropy_pool.entropy_buff)){
		goto err;
	}

	ret = 0;

err:
	if(ret && (buf != NULL)){
		(*buf) = NULL;
	}
	return ret;
}

int clear_entropy_input(uint8_t *buf)
{
	int ret = -1;
	uint8_t *buf_max = (curr_entropy_pool.entropy_buff + curr_entropy_pool.entropy_buff_pos);

	/* Sanity check */
	if((buf < curr_entropy_pool.entropy_buff) || (buf > buf_max)){
		goto err;
	}

	/* Clean the buffer until pos */
	memset(curr_entropy_pool.entropy_buff, 0, curr_entropy_pool.entropy_buff_pos);

	ret = 0;
err:
	return ret;
}

/****************************************************************************/
#else /* !WITH_TEST_ENTROPY_SOURCE */
/*
 * The following function is an entropy gatherer used by DRBG layers.
 *
 * NOTE:XXX: this function MUST be properly implemented by the user!
 * For now, this returns an error on purpose so that the user is aware
 * of the need of implementing this.
 * Proper entropy sources must be used as the whole security of the DRBG
 * is based on this. The DRBG per se is only a deterministic algorithm
 * allowing for robustness and backward/forward secrecy insurance, but
 * the output entropy is as strong as the entropy sources feeding it!
 *
 * => Please refer to NIST SP 800-90B "Recommendation for the Entropy
 *    Sources Used for Random Bit Generation" for more insight on how
 *    to handle entropy sources feeding the DRBG algorithms.
 */
int get_entropy_input(uint8_t **in, uint32_t len, bool prediction_resistance)
{
	int ret;

	/* Avoid unused parameter warnings */
	(void)in;
	(void)len;
	(void)prediction_resistance;

	printf("Error: please provide your implementation of entropy gathering in the file '%s'!\n", __FILE__);
	ret = -1;

	return ret;
}

int clear_entropy_input(uint8_t *buf)
{
	int ret;
	/* Avoid unused parameter warnings */
	(void)buf;

	printf("Error: please provide your implementation of entropy clearing in the file '%s'!\n", __FILE__);
	ret = -1;

	return ret;
}

#endif /* !WITH_TEST_ENTROPY_SOURCE */
