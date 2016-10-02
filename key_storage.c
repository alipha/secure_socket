#include "key_storage.h"
#include "base64.h"
#include <sodium.h>


// password can be NULL
ss_error ss_encode_public_key(const ss_public_key *public_key, char *encoded, int encoded_max) {
}

ss_error ss_encode_key_pair(const ss_key_pair *key_pair, char *encoded, int encoded_max, BOOL remove_password) {
}

ss_error ss_encode_shared_key(const ss_shared_key *shared_key, char *encoded, int encoded_max, BOOL remove_password) {
}


// password can be NULL
ss_error ss_decode_public_key(const char *encoded, ss_public_key *public_key) {
}

ss_error ss_decode_key_pair(const char *encoded, const char *private_key_password, ss_key_pair *key_pair) {
}

ss_error ss_decode_shared_key(const char *encoded, const char *password, ss_shared_key *shared_key) {
}




