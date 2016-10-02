#include "secure_socket.h"
#include <string.h>
#include <sodium.h>


ss_error generate_secret_key(unsigned char *secret_key, size_t key_len, ss_key_derivation_info *key_info, const char *password);


static ss_settings settings = {
	crypto_pwhash_OPSLIMIT_INTERACTIVE,
	crypto_pwhash_MEMLIMIT_INTERACTIVE
};


void get_settings(ss_settings *s) {
	*s = settings;
}

void set_settings(ss_settings *s) {
	settings = *s;
}

 
ss_error ss_generate_key_pair(ss_key_pair *key_pair, const char *private_key_password) {

	ss_error error = generate_secret_key(key_pair->private_key, sizeof key_pair->private_key, &key_pair->key_info, private_key_password);

	if(error)
		return error;

	crypto_scalarmult_base(key_pair->public_key->value, key_pair->private_key);
	return SS_SUCCESS;
}


ss_error ss_generate_shared_key(ss_shared_key *shared_key, const char *password) {
	
	return generate_secret_key(shared_key->value, sizeof shared_key->value, &shared_key->key_info, password);
}



ss_error generate_secret_key(unsigned char *secret_key, size_t key_len, ss_key_derivation_info *key_info, const char *password) {

	unsigned char key_and_verification[(SS_PRIVATE_KEY_LENGTH > SS_SHARED_KEY_LENGTH ? SS_PRIVATE_KEY_LENGTH : SS_SHARED_KEY_LENGTH) + SS_KEY_VERIFICATION_LENGTH];


	if(password && password[0]) {
		randombytes_buf(key_info->salt, sizeof key_info->salt);

		if(crypto_pwhash(key_and_verification, key_len + SS_KEY_VERIFICATION_LENGTH, password, strlen(password), salt, settings.password_iterations, settings.password_memory, crypto_pwhash_ALG_DEFAULT) != 0)
			return SS_ERROR_OUT_OF_MEMORY;

		key_info->version = 1;
		key_info->iterations = settings.password_iterations;
		key_info->memory = settings.password_memory;

		memcpy(secret_key, key_and_verification, key_len);
		memcpy(key_info->verification, key_and_verification + key_len, SS_KEY_VERIFICATION_LENGTH);

	} else {
		key_info->version = 0;
		key_info->iterations = 0;
		key_info->memory = 0;
		randombytes_buf(secret_key, key_len);
	}

	return SS_SUCCESS;
}


secure_socket* ss_socket(const ss_key_pair *my_key_pair) {
}


