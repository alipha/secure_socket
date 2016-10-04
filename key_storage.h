#ifndef SS_KEY_STORAGE_H
#define SS_KEY_STORAGE_H

#include "secure_socket.h"


// password can be NULL for any of the functions
ss_error ss_generate_key_pair(ss_key_pair *key_pair, const char *private_key_password);
ss_error ss_generate_shared_key(ss_shared_key *shared_key, const char *password);

ss_error ss_encode_public_key(char *encoded, size_t encoded_max, const ss_public_key *public_key);
ss_error ss_encode_key_pair(char *encoded, size_t encoded_max, const ss_key_pair *key_pair);
ss_error ss_encode_shared_key(char *encoded, size_t encoded_max, const ss_shared_key *shared_key);

ss_error ss_decode_public_key(ss_public_key *public_key, const char *encoded);
ss_error ss_decode_key_pair(ss_key_pair *key_pair, const char *encoded, const char *private_key_password);
ss_error ss_decode_shared_key(ss_shared_key *shared_key, const char *encoded, const char *password);

BOOL ss_private_key_has_password(ss_key_pair *key_pair);
BOOL ss_shared_key_has_password(ss_shared_key *shared_key);

ss_error ss_change_private_key_password(ss_key_pair *key_pair, const char *new_password);
ss_error ss_change_shared_key_password(ss_shared_key *shared_key, const char *new_password);

#endif
