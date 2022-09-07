/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MUST_HAVE(cond, ret, lbl) do {		\
	if (!(cond)) {				\
		ret = -1;			\
		goto lbl;			\
	}					\
}  while (0)

#define EG(cond,lbl) do { if (cond) { goto lbl ; } } while (0)

#define LOCAL_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define LOCAL_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define BYTECEIL(numbits) (((numbits) + 7) / 8)

#define VAR_ZEROIFY(x) do {			\
		x = 0;				\
	} while (0)

#define PTR_NULLIFY(x) do {			\
		x = NULL;			\
	} while (0)

/* Return 1 if architecture is big endian, 0 otherwise. */
static inline int arch_is_big_endian(void)
{
	const uint16_t val = 0x0102;
	const uint8_t *buf = (const uint8_t *)(&val);

	return buf[0] == 0x01;
}


#endif /* __UTILS_H__ */
