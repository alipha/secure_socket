#include "secure_socket.h"
#include "impl.h"
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


static ss_error do_connect(secure_socket *sock, const char *host, int port);
static ss_error do_listen(secure_socket *sock, int port);


static ss_settings settings = {
	crypto_pwhash_OPSLIMIT_INTERACTIVE,
	crypto_pwhash_MEMLIMIT_INTERACTIVE >> 10
};


void ss_get_settings(ss_settings *s) {
	if(s)
		*s = settings;
}

void ss_set_settings(ss_settings *s) {
	if(s)
		settings = *s;
}

 

secure_socket* ss_socket_init(const ss_key_pair *my_key_pair) {  // my_key_pair may be NULL
	secure_socket *sock = ss_malloc(sizeof(secure_socket));

	if(!sock)
		return NULL;

	memset(sock, 0, sizeof *sock);
	sock->state = STATE_INIT;
	sock->current_input_frame = NULL;

	if(my_key_pair) {
		memcpy(sock->master_private_key, my_key_pair->private_key, sizeof sock->master_private_key);
		memcpy(sock->my_hello.master_public_key, my_key_pair->public_key.value, sizeof sock->my_hello.master_public_key);
		sock->my_hello.header.provided_fields |= PROVIDED_MASTER_PUBLIC_KEY;
	}

	sock->my_hello.header.message_type = MESSAGE_TYPE_HELLO;
	sock->my_hello.header.status = STATUS_GOOD;
 	sock->my_hello.header.provided_fields |= PROVIDED_VERSION | PROVIDED_EPHEMERAL_PUBLIC_KEY;

	sock->my_hello.version = 1;
	// TODO: generate_keypair(sock->my_hello.ephemeral_public_key, sock->ephemeral_private_key);
	sock->ephemeral_key_creation_time = time(NULL);

	// TODO: sock->my_hello.header.length = ;
	// TODO: sock->their_nonce[NONCE_LENGTH - 1] = 1; or my_nonce

	// set my_hello
	return sock;
}


ss_error ss_shared_key_connect(secure_socket *sock, const char *host, int port, const ss_shared_key *shared_key) {
	if(!sock || !host || !shared_key)
		return SS_ERROR_NULL_ARGUMENT;

	// TODO
	return do_connect(sock, host, port);
}


ss_error ss_public_key_connect(secure_socket *sock, const char *host, int port, const ss_public_key *server_public_key) {
	if(!sock || !host || !server_public_key)
		return SS_ERROR_NULL_ARGUMENT;
	
	// TODO
	return do_connect(sock, host, port);
}



ss_error ss_shared_key_listen(secure_socket *sock, int port, const ss_shared_key *shared_key) {
	if(!sock || !shared_key)
		return SS_ERROR_NULL_ARGUMENT;

	// TODO
	return do_listen(sock, port);
}


ss_error ss_public_key_listen(secure_socket *sock, int port, const ss_public_key *client_public_keys, size_t key_count) {
	if(!sock || (!client_public_keys && key_count > 0))
		return SS_ERROR_NULL_ARGUMENT;

	// TODO
	return do_listen(sock, port);
}



void ss_socket_free(secure_socket *sock) {
	if(sock) {
		close(sock->socket);
		ss_malloc_free(sock->current_input_frame);
	}

	ss_malloc_free(sock);
}


ss_error do_connect(secure_socket *sock, const char *host, int port) {
	if(port < 1 || port > 65535)
		return SS_ERROR_INVALID_PORT;

	// TODO
	return SS_SUCCESS;
}


ss_error do_listen(secure_socket *sock, int port) {
	if(port < 1 || port > 65535)
		return SS_ERROR_INVALID_PORT;

	// TODO
	return SS_SUCCESS;
}
