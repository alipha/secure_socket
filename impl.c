#include "impl.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

// not using libsodium's constants directly because if there were any changes to
// them, that would break the protocol
#if EPHEMERAL_PUBLIC_KEY_LENGTH != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#error "EPHEMERAL_PUBLIC_KEY_LENGTH does not match libsodium's crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES"
#endif

#if EPHEMERAL_PRIVATE_KEY_LENGTH != crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#error "EPHEMERAL_PRIVATE_KEY_LENGTH does not match libsodium's crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES"
#endif

#if SIGNATURE_LENGTH != crypto_sign_ed25519_BYTES
#error "SIGNATURE_LENGTH does not match libsodium's crypto_sign_ed25519_BYTES"
#endif

#if TAG_LENGTH != crypto_aead_chacha20poly1305_ABYTES
#error "TAG_LENGTH does not match libsodium's crypto_aead_chacha20poly1305_ABYTES"
#endif

#if NONCE_LENGTH != crypto_aead_chacha20poly1305_NPUBBYTES
#error "NONCE_LENGTH does not match libsodium's crypto_aead_chacha20poly1305_NPUBBYTES"
#endif


void (*ss_random)(void * const buf, const size_t size) = randombytes_buf;
int (*ss_sign_keypair)(unsigned char *, unsigned char*) = crypto_sign_ed25519_keypair;

void* (* volatile ss_memset)(void *, int, size_t) = memset;

void* (*ss_malloc)(size_t) = malloc;
void (*ss_malloc_free)(void *) = free;


void ss_sign_message(unsigned char *signature, const void *message, size_t message_len, const ss_key_pair *key_pair) {
	unsigned char combined_key[COMBINED_KEY_LENGTH];

	assert(signature != NULL);
	assert(message != NULL);
	assert(key_pair != NULL);

	memcpy(combined_key, key_pair->private_key, sizeof key_pair->private_key);
	memcpy(combined_key + sizeof key_pair->private_key, key_pair->public_key.value, sizeof key_pair->public_key.value);

	crypto_sign_ed25519_detached(signature, NULL, message, message_len, combined_key);
	ss_memset(combined_key, 0, sizeof combined_key);
}


BOOL ss_verify_signature(const unsigned char *signature, const void *message, size_t message_len, ss_public_key *public_key) {
	assert(signature != NULL);
	assert(message != NULL);
	assert(public_key != NULL);

	return crypto_sign_ed25519_verify_detached(signature, message, message_len, public_key->value) == 0;
}


void increment_nonce_by_2(unsigned char *nonce) {
	nonce[NONCE_LENGTH - 1] += 2;

	if(nonce[NONCE_LENGTH - 1] > 1)	// there was no wrap around (carry-over)
		return;

	for(int i = NONCE_LENGTH - 2; i >= 0; i--) {  // wrap around should never happen in practical usage
		nonce[i]++;
		if(nonce[i] > 0)
			return;
	}
}
 
