/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr> 
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#ifndef GET_UINT8_BE
#define GET_UINT8_BE(n, b, i)			  	\
do {						    	\
	(n) = (uint8_t)(b)[(i)];			\
} while( 0 )
#endif
#ifndef PUT_UINT8_BE
#define PUT_UINT8_BE(n, b, i)				\
do {	  						\
	(b)[(i)     ] = (uint8_t)(n);	   		\
} while( 0 )
#endif

#define GET_UINT8_LE GET_UINT8_BE

#define PUT_UINT8_LE PUT_UINT8_BE

/*
 * 16-bit integer manipulation macros
 */
#ifndef GET_UINT16_BE
#define GET_UINT16_BE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint16_t) (b)[(i)    ]) << 16 )   \
		| ( ((uint16_t) (b)[(i) + 1])       );	\
} while( 0 )
#endif
#ifndef PUT_UINT16_BE
#define PUT_UINT16_BE(n, b, i)				\
do {	  						\
	(b)[(i)    ] = (uint8_t) ( (n) >> 16 );      	\
	(b)[(i) + 1] = (uint8_t) ( (n)       );      	\
} while( 0 )
#endif
#ifndef GET_UINT16_LE
#define GET_UINT16_LE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint16_t) (b)[(i)    ])       )   \
		| ( ((uint16_t) (b)[(i) + 1]) << 16 );	\
} while( 0 )
#endif
#ifndef PUT_UINT16_LE
#define PUT_UINT16_LE(n, b, i)				\
do {	  						\
	(b)[(i)    ] = (uint8_t) ( (n)       );      	\
	(b)[(i) + 1] = (uint8_t) ( (n) >> 16 );      	\
} while( 0 )
#endif

/*
 * 32-bit integer manipulation macros
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint32_t) (b)[(i)    ]) << 24 )   \
		| ( ((uint32_t) (b)[(i) + 1]) << 16 )	\
		| ( ((uint32_t) (b)[(i) + 2]) <<  8 )	\
		| ( ((uint32_t) (b)[(i) + 3])       );  \
} while( 0 )
#endif
#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)				\
do {	  						\
	(b)[(i)    ] = (uint8_t) ( (n) >> 24 );      	\
	(b)[(i) + 1] = (uint8_t) ( (n) >> 16 );      	\
	(b)[(i) + 2] = (uint8_t) ( (n) >>  8 );      	\
	(b)[(i) + 3] = (uint8_t) ( (n)       );      	\
} while( 0 )
#endif
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint32_t) (b)[(i)    ])       )   \
		| ( ((uint32_t) (b)[(i) + 1]) <<  8 )	\
		| ( ((uint32_t) (b)[(i) + 2]) << 16 )	\
		| ( ((uint32_t) (b)[(i) + 3]) << 24 );  \
} while( 0 )
#endif
#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n, b, i)				\
do {	  						\
	(b)[(i)    ] = (uint8_t) ( (n)       );      	\
	(b)[(i) + 1] = (uint8_t) ( (n) >> 8  );      	\
	(b)[(i) + 2] = (uint8_t) ( (n) >> 16 );      	\
	(b)[(i) + 3] = (uint8_t) ( (n) >> 24 );      	\
} while( 0 )
#endif

/*
 * 64-bit integer manipulation macros
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint64_t) (b)[(i)    ]) << 56 )  	\
		| ( ((uint64_t) (b)[(i) + 1]) << 48 )	\
		| ( ((uint64_t) (b)[(i) + 2]) << 40 )	\
		| ( ((uint64_t) (b)[(i) + 3]) << 32 )   \
		| ( ((uint64_t) (b)[(i) + 4]) << 24 )	\
		| ( ((uint64_t) (b)[(i) + 5]) << 16 )	\
		| ( ((uint64_t) (b)[(i) + 6]) <<  8 )   \
		| ( ((uint64_t) (b)[(i) + 7])       );  \
} while( 0 )
#endif
#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n, b, i)	    			\
do {				      			\
    (b)[(i)    ] = (uint8_t) ( (n) >> 56 );  		\
    (b)[(i) + 1] = (uint8_t) ( (n) >> 48 );  		\
    (b)[(i) + 2] = (uint8_t) ( (n) >> 40 );  		\
    (b)[(i) + 3] = (uint8_t) ( (n) >> 32 );  		\
    (b)[(i) + 4] = (uint8_t) ( (n) >> 24 );  		\
    (b)[(i) + 5] = (uint8_t) ( (n) >> 16 );  		\
    (b)[(i) + 6] = (uint8_t) ( (n) >>  8 );  		\
    (b)[(i) + 7] = (uint8_t) ( (n)       );  		\
} while( 0 )
#endif
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n, b, i)			  	\
do {						    	\
	(n) =     ( ((uint64_t) (b)[(i)    ])       )  	\
		| ( ((uint64_t) (b)[(i) + 1]) <<  8 )	\
		| ( ((uint64_t) (b)[(i) + 2]) << 16 )	\
		| ( ((uint64_t) (b)[(i) + 3]) << 24 )   \
		| ( ((uint64_t) (b)[(i) + 4]) << 32 )	\
		| ( ((uint64_t) (b)[(i) + 5]) << 40 )	\
		| ( ((uint64_t) (b)[(i) + 6]) << 48 )   \
		| ( ((uint64_t) (b)[(i) + 7]) << 56 );  \
} while( 0 )
#endif
#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n, b, i)	    			\
do {				      			\
    (b)[(i)    ] = (uint8_t) ( (n) >> 56 );  		\
    (b)[(i) + 1] = (uint8_t) ( (n) >> 48 );  		\
    (b)[(i) + 2] = (uint8_t) ( (n) >> 40 );  		\
    (b)[(i) + 3] = (uint8_t) ( (n) >> 32 );  		\
    (b)[(i) + 4] = (uint8_t) ( (n) >> 24 );  		\
    (b)[(i) + 5] = (uint8_t) ( (n) >> 16 );  		\
    (b)[(i) + 6] = (uint8_t) ( (n) >>  8 );  		\
    (b)[(i) + 7] = (uint8_t) ( (n)       );  		\
} while( 0 )
#endif

/*
 * A simple adder with carry for our operations.
 * We adapt to our string size with optimizations.
 */
#define INTEGER_ADD(A, B, C, size, type, GET, PUT) do {	\
        uint32_t i;					\
        type tmp, carry1, carry2, _carry = 0;		\
        for(i = 0; i < size; i++){			\
                type a, b, c;				\
                uint32_t idx = (size - i - 1);		\
		GET(a, A, (idx * sizeof(type)));	\
		GET(b, B, (idx * sizeof(type)));	\
                tmp = (type)(a + b);			\
                carry1 = (type)(tmp < a);		\
                c = (type)(tmp + _carry);		\
                carry2 = (type)(c < tmp);		\
                _carry = (type)(carry1 | carry2);	\
		PUT(c, C, (idx * sizeof(type)));	\
        }						\
} while(0)

static inline void integer_sum(const uint8_t *A, const uint8_t *B, uint8_t *C, uint32_t size)
{
#ifdef OPTIMIZE_ADD_OP
	if((size % 8) == 0){
		INTEGER_ADD(A, B, C, (size / 8), uint64_t, GET_UINT64_BE, PUT_UINT64_BE);
	}
	else if((size % 4) == 0){
		INTEGER_ADD(A, B, C, (size / 4), uint32_t, GET_UINT32_BE, PUT_UINT32_BE);
	}
	else if((size % 2) == 0){
		INTEGER_ADD(A, B, C, (size / 2), uint16_t, GET_UINT16_BE, PUT_UINT16_BE);
	}
	else{
		INTEGER_ADD(A, B, C, (size), uint8_t, GET_UINT8_BE, PUT_UINT8_BE);
	}
#else
	INTEGER_ADD(A, B, C, (size), uint8_t, GET_UINT8_BE, PUT_UINT8_BE);
#endif
	return;
}


/* A simple incrementer with carry for our
 * operations.
 * We adapt to our string size with optimizations.
 */
#define INTEGER_INC(A, C, size, type, GET, PUT) do {	\
	uint32_t i;					\
	type _carry = 1;				\
	for(i = 0; i < (size); i++){			\
		type a, c;				\
		uint32_t idx = (size - i - 1);		\
		GET(a, A, (idx * sizeof(type)));	\
		c = (type)(a + _carry);			\
		_carry = (type)(c < a);			\
		PUT(c, C, (idx * sizeof(type)));	\
	}						\
} while(0)

static inline void integer_inc(const uint8_t *A, uint8_t *C, uint32_t size)
{
#ifdef OPTIMIZE_ADD_OP
	if((size % 8) == 0){
		INTEGER_INC(A, C, (size / 8), uint64_t, GET_UINT64_BE, PUT_UINT64_BE);
	}
	else if((size % 4) == 0){
		INTEGER_INC(A, C, (size / 4), uint32_t, GET_UINT32_BE, PUT_UINT32_BE);
	}
	else if((size % 2) == 0){
		INTEGER_INC(A, C, (size / 2), uint16_t, GET_UINT16_BE, PUT_UINT16_BE);
	}
	else{
		INTEGER_INC(A, C, (size), uint8_t, GET_UINT8_BE, PUT_UINT8_BE);
	}
#else
	INTEGER_INC(A, C, (size), uint8_t, GET_UINT8_BE, PUT_UINT8_BE);
#endif
	return;
}

__attribute__((used)) static inline void hexdump(const char* prefix, const char *in, unsigned int len){
        unsigned int i;
        if(prefix != NULL){
                printf("%s", prefix);
        }
        if(in != NULL){
                for(i = 0; i < len; i++){
                        printf("%02x", (unsigned char)in[i]);
                }
                printf("\n");
        }
}

/* Our scatter/gather structure */
typedef struct {
	const unsigned char *data;
	uint32_t data_len;
} in_scatter_data;

#define ATTRIBUTE_UNUSED __attribute__((unused))

#endif /* __HELPERS_H__ */
