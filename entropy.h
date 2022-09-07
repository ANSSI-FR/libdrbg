/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __ENTROPY_H__
#define __ENTROPY_H__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

int get_entropy_input(uint8_t **in, uint32_t len, bool prediction_resistance);

int clear_entropy_input(uint8_t *buf);

#endif /* __ENTROPY_H__ */
