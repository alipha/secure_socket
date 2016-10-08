#include "secure_socket.h"
#include <string.h>
#include <sodium.h>


// not using libsodium's constants directly because if there were any changes to
// them, that would break the protocol
#if SS_PUBLIC_KEY_LENGTH != crypto_sign_ed25519_PUBLICKEYBYTES
#error "SS_PUBLIC_KEY_LENGTH does not match libsodium's crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#if SS_PUBLIC_KEY_LENGTH + SS_PRIVATE_KEY_LENGTH != crypto_sign_ed25519_SECRETKEYBYTES
#error "SS_PRIVATE_KEY_LENGTH does not match what is expected to work with libsodium"
#endif

#if SS_SHARED_KEY_LENGTH != crypto_aead_chacha20poly1305_KEYBYTES
#error "SS_SHARED_KEY_LENGTH does not match libsodium's crypto_aead_chacha20poly1305_KEYBYTES"
#endif

#if SS_KEY_SALT_LENGTH != crypto_pwhash_argon2i_SALTBYTES
#error "SS_KEY_SALT_LENGTH does not match libsodium's crypto_pwhash_argon2i_SALTBYTES"
#endif



static ss_settings settings = {
	crypto_pwhash_OPSLIMIT_INTERACTIVE,
	crypto_pwhash_MEMLIMIT_INTERACTIVE >> 10
};


void ss_get_settings(ss_settings *s) {
	*s = settings;
}

void ss_set_settings(ss_settings *s) {
	settings = *s;
}

 

#include <stdio.h>

secure_socket* ss_socket(const ss_key_pair *my_key_pair) {
	printf("%d", (int)my_key_pair->private_key_info.version);  // TODO: just do something for now to get rid of warnings
	return NULL;
}


