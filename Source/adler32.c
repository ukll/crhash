#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../crhash.h"
#include "../Header/adler32.h"


bool
digest_adler32(const crhash_param_st params)
{
	printf("%x\n", adler32((unsigned char *)params.data));

	return true;
}

bool
check_adler32(const crhash_param_st params)
{
	char calculated_hash[MAX_HASH_LENGTH];

	sprintf(calculated_hash, "%x", adler32((unsigned char *)params.data));

	if (strcmp(params.hash, calculated_hash) != 0) {
		puts("false");
		return false;
	}

	puts("true");
	return true;
}



#define MOD_ADLER 65521 /* largest prime smaller than 65536 */

uint32_t
adler32(const unsigned char *data)
{
	uint32_t a = 1, b = 0;
	uint32_t index;

	/* Process each byte of the data in order */
	for (index = 0; index < strlen((const char *)data); ++index)
	{
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}

	return (b << 16) | a;
}


