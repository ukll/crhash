/*
 * adler32.h
 *
 */

#ifndef HEADER_ADLER32_H
#define HEADER_ADLER32_H

#include <stdint.h>

#include "../crhash.h"

bool digest_adler32(const crhash_param_st params);
bool check_adler32(const crhash_param_st params);
uint32_t adler32(const unsigned char *data);

#endif /* HEADER_ADLER32_H */
