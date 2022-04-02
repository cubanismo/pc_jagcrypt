#include <stdint.h>

#ifndef EXTERN
#define EXTERN extern
#endif

#define KEYSIZE 66

/*
 * big numbers for RSA
 */
EXTERN unsigned char A_num[KEYSIZE], B_num[KEYSIZE], C_num[KEYSIZE], N_num[KEYSIZE];


/*
 * function to get a 32-bit integer from a stream of bytes
 */
#define Getlong(x) ( ((int32_t)(x)[0] << 24) | ((int32_t)(x)[1] << 16) | ((int32_t)(x)[2] << 8) | ((int32_t)(x)[3]) )
