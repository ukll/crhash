/*
 * crhash.h
 *
 */

#ifndef CRHASH_H
#define CRHASH_H

/*
 * Allowed operations
 */
#define OP_NAME_LENGTH 10		// Maximum length of an operation name
#define OPERATION_COUNT 4		// Total count of operations allowed

const static char operations[OPERATION_COUNT][OP_NAME_LENGTH] = {
	"digest", "check", "encrpt", "decrypt"
};


/*
 * Supported algorithms
 */
#define ALG_NAME_LENGTH 26		// Maximum length of an algorithm name
#define DIGEST_ALG_COUNT 23		// Total count of digest algorithms
#define ENCRYPT_ALG_COUNT 15	// Total count of encryption algorithms

const static char digest_algorithms[DIGEST_ALG_COUNT][ALG_NAME_LENGTH] = {
	"adler32",
	"base32", "base58", "base64",
	"crc32",
	"fletcher16", "fletcher32",
	"md2", "md4", "md5", "md6",
	"sha2_224", "sha2_256", "sha2_384",	"sha2_512", "sha2_512_224", "sha2_512_256",
	"sha3_224", "sha3_256", "sha3_384",	"sha3_512",
	"shake128", "shake256"
};

const static char encrypt_algorithms[ENCRYPT_ALG_COUNT][ALG_NAME_LENGTH] = {
	"blowfish",
	"md5", "md6",
	"sha2_224", "sha2_256", "sha2_384",	"sha2_512", "sha2_512_224", "sha2_512_256",
	"sha3_224", "sha3_256", "sha3_384",	"sha3_512",
	"shake128", "shake256"
};


/*
 * struct to store argument parameters for processing
 */
#define MAX_SALT_LENGTH 129
#define MAX_HASH_LENGTH 513
#define MAX_KEY_LENGTH 4097
#define MAX_DATA_LENGTH 16385

typedef struct {
	char operation[OP_NAME_LENGTH];
	char algorithm[ALG_NAME_LENGTH];
	char salt[MAX_SALT_LENGTH];
	uint8_t iteration;
	char hash[MAX_HASH_LENGTH];
	char key[MAX_KEY_LENGTH];
	char data[MAX_DATA_LENGTH];
} crhash_param_st;

#endif /* CRHASH_H */
