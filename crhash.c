#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "crhash.h"
#include "Header/adler32.h"

extern const char operations[OPERATION_COUNT][OP_NAME_LENGTH];
extern const char digest_algorithms[DIGEST_ALG_COUNT][ALG_NAME_LENGTH];
extern const char encrypt_algorithms[ENCRYPT_ALG_COUNT][ALG_NAME_LENGTH];

bool parse_params(const int argc, const char *argv[], crhash_param_st *crhash_params);
bool check_optype(const char *optype);
bool check_algorithm(const char *algorithm);

bool crhash_digest(const crhash_param_st params);
bool crhash_check(const crhash_param_st params);
bool crhash_encrypt(const crhash_param_st params);
bool crhash_decrypt(const crhash_param_st params);

int
main(int argc, char *argv[])
{
	// Object to store parameters and values.
	crhash_param_st crhash_params = { "", "", "", 0, "", "", "" };

	/*
	 * Check if the parameters are valid.
	 */
    if (!parse_params(argc, (const char **)argv, &crhash_params)){
    	puts("Parameters are not valid!");
    	return EXIT_FAILURE;
    }

    /*
     * Parameter parse successful.
     * Start operation.
     */
    if (strcmp(crhash_params.operation, "digest") == 0) {

    	if (!crhash_digest(crhash_params)) {
    		return EXIT_FAILURE;
    	}

    } else if (strcmp(crhash_params.operation, "check") == 0) {

    	if (!crhash_check(crhash_params)) {
    		return EXIT_FAILURE;
    	}

    } else if (strcmp(crhash_params.operation, "encrypt") == 0) {

    	if (!crhash_encrypt(crhash_params)) {
    		return EXIT_FAILURE;
    	}

    } else if (strcmp(crhash_params.operation, "decrypt") == 0) {

    	if (!crhash_decrypt(crhash_params)) {
    		return EXIT_FAILURE;
    	}

    }

	return EXIT_SUCCESS;
}

/**
 * Parse all the provided arguments
 */
bool
parse_params(const int argc, const char *argvector[], crhash_param_st *crhash_params)
{
	/*
	 * If argc is not an odd number, then there is a problem.
	 *
	 * If argc is less then 7, then operation, algorithm and data
	 * were not provided with the corresponding options.
	 *
	 * If argc is greater than 15, then there is/are unsupported option(s).
	 */
	if (argc % 2 != 1 || argc < 7 || argc > 15) {
		puts("Illegal number of arguments!");
		return false;
	}

	// OPERATION 	= 'o'
	// ALGORITHM 	= 'a'
	// SALT 		= 's'
	// ITERATION 	= 'i'
	// HASH 		= 'h'
	// KEY 			= 'k'
	// DATA 		= 'd'
	for(register uint8_t param = 1; param < argc; param += 2) {

		if (strcmp(argvector[param], "-o") == 0) {
			// Check if the current parameter option is OPERATION = '-o'

			if (check_optype(argvector[param + 1])) {
				strcpy(crhash_params->operation, argvector[param + 1]);
			} else {
				return false;
			}

		} else if (strcmp(argvector[param], "-a") == 0) {
			// Check if the current parameter option is ALGORITHM = '-a'

			if (check_algorithm(argvector[param + 1])) {
				strcpy(crhash_params->algorithm, argvector[param + 1]);
			} else {
				return false;
			}

		} else if (strcmp(argvector[param], "-s") == 0) {
			// Check if the current parameter option is SALT = '-s'

			if (strlen(argvector[param + 1]) < MAX_SALT_LENGTH) {
				// Copy the salt
				strcpy(crhash_params->salt, argvector[param + 1]);
			} else {
				strncpy(crhash_params->salt, argvector[param + 1], (MAX_SALT_LENGTH - 1));
				crhash_params->salt[MAX_SALT_LENGTH - 1] = '\0';
			}

		} else if (strcmp(argvector[param], "-i") == 0) {

			/* Check if the iteration count is uint8_t.
			 * If so, copy it.
			 */
			if (sscanf(argvector[param + 1], "%"SCNu8"\n", &crhash_params->iteration) != 1) {
				printf("%s is not a valid iteration count!\n", argvector[param + 1]);
				return false;
			}

		} else if (strcmp(argvector[param], "-h") == 0) {
			// Check if the current parameter option is HASH = '-h'

			// Copy the hash
			if (strlen(argvector[param + 1]) < MAX_HASH_LENGTH) {
				strcpy(crhash_params->hash, argvector[param + 1]);
			} else {
				strncpy(crhash_params->hash, argvector[param + 1], (MAX_HASH_LENGTH - 1));
				crhash_params->hash[MAX_HASH_LENGTH - 1] = '\0';
			}

		} else if (strcmp(argvector[param], "-k") == 0) {
			// Check if the current parameter option is KEY = '-k'

			// Copy the key
			if (strlen(argvector[param + 1]) < MAX_KEY_LENGTH) {
				strcpy(crhash_params->key, argvector[param + 1]);
			} else {
				strncpy(crhash_params->key, argvector[param + 1], (MAX_KEY_LENGTH - 1));
				crhash_params->key[MAX_KEY_LENGTH - 1] = '\0';
			}

		} else if (strcmp(argvector[param], "-d") == 0) {
			// Check if the current parameter option is DATA = '-d'

			// Copy the data
			if (strlen(argvector[param + 1]) < MAX_DATA_LENGTH) {
				strcpy(crhash_params->data, argvector[param + 1]);
			} else {
				strncpy(crhash_params->data, argvector[param + 1], (MAX_DATA_LENGTH - 1));
				crhash_params->data[MAX_DATA_LENGTH - 1] = '\0';
			}

		} else {
			// An unknown option has been encountered.

			printf("%s is not a valid option!\n", argvector[param]);
			return false;
		}
	}

	return true;
}

/*
 * Check if the operation is an allowed one.
 */
bool
check_optype(const char *optype)
{
	for (register uint8_t i = 0; i < OPERATION_COUNT; i++) {
		if (strcmp(operations[i], optype) == 0) {
			return true;
		}
	}

	printf("%s is not a valid operation type!\n", optype);
	return false;
}

/*
 * Check if the algorithm is a supported one.
 */
bool
check_algorithm(const char *algorithm)
{
	register uint8_t i;

	// Check if the algorithm is in digest_algorithms
	for (i = 0; i < DIGEST_ALG_COUNT; i++) {
		if (strcmp(digest_algorithms[i], algorithm) == 0) {
			return true;
		}
	}

	// Check if the algorithm is in encrypt_algorithms
	for (i = 0; i < ENCRYPT_ALG_COUNT; i++) {
		if (strcmp(encrypt_algorithms[i], algorithm) == 0) {
			return true;
		}
	}

	printf("%s is not a valid algorithm!\n", algorithm);
	return false;
}

bool
crhash_digest(const crhash_param_st params)
{
	bool alg_valid = false;

	if (strlen(params.data) == 0) {
		puts("Data string was not provided!");
		return false;
	}

	// Check if the algorithms is a supported digest algorithm.
	for (register uint8_t index = 0; index < DIGEST_ALG_COUNT; index++) {
		if (strcmp(digest_algorithms[index], params.algorithm) == 0) {
			alg_valid = true;
		}
	}

	if (!alg_valid) {
		puts("The provided algorithm is not a supported digest algorithm!");
		return false;
	}

	if (strcmp(params.algorithm, "adler32") == 0) {

		if (!digest_adler32(params)) {
			return false;
		}

	} /*else if (strcmp(params.algoritm, "crc32") == 0) {

	}*/

	return true;
}

bool
crhash_check(const crhash_param_st params)
{
	bool alg_valid = false;

	if (strlen(params.data) == 0) {
		puts("Data string was not provided!");
		return false;
	}

	if (strlen(params.hash) == 0) {
		puts("Hash string was not provided!");
		return false;
	}

	// Check if the algorithms is a supported digest algorithm.
	for (register uint8_t index = 0; index < DIGEST_ALG_COUNT; index++) {
		if (strcmp(digest_algorithms[index], params.algorithm) == 0) {
			alg_valid = true;
		}
	}

	if (!alg_valid) {
		puts("The provided algorithm is not a supported digest algorithm!");
		return false;
	}

	if (strcmp(params.algorithm, "adler32") == 0) {

		if (!check_adler32(params)) {
			return false;
		}

	} /*else if (strcmp(params.algoritm, "crc32") == 0) {

	}*/

	return true;
}

bool
crhash_encrypt(const crhash_param_st params)
{
	return true;
}

bool
crhash_decrypt(const crhash_param_st params)
{
	return true;
}
