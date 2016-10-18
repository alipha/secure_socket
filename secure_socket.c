#include "secure_socket.h"
#include "impl.h"
#include <string.h>
#include <assert.h>
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
static ss_error make_connection(secure_socket *sock, const char *host, int port);
static ss_error perform_handshake(secure_socket *sock);

static ss_error send_hello(secure_socket *sock);
static ss_error receive_hello(secure_socket *sock);
static ss_error send_finish(secure_socket *sock);
static ss_error receive_finish(secure_socket *sock);
static void generate_finish(handshake_finish *finish, unsigned char *combined_hellos, secure_socket *sock, unsigned char *first_hello, size_t first_hello_len, unsigned char *second_hello, size_t second_hello_len);

static ss_error receive_exact(secure_socket *sock, unsigned char *buffer, size_t amount);
static ss_error receive_message(secure_socket *sock, unsigned char **buffer_ptr, size_t buffer_max);


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
	sock->their_public_keys = NULL;
	sock->current_input_frame = NULL;

	if(my_key_pair) {
		memcpy(sock->master_private_key, my_key_pair->private_key, sizeof sock->master_private_key);
		memcpy(sock->my_hello.master_public_key, my_key_pair->public_key.value, sizeof sock->my_hello.master_public_key);
		sock->my_hello.header.provided_fields |= PROVIDED_MASTER_PUBLIC_KEY;
	}

	sock->my_hello.header.message_type = MESSAGE_TYPE_HELLO;
	sock->my_hello.header.status = STATUS_GOOD;
 	sock->my_hello.header.provided_fields |= PROVIDED_EPHEMERAL_PUBLIC_KEY;

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

	memcpy(sock->shared_key, shared_key->value, sizeof sock->shared_key);
	return do_connect(sock, host, port);
}


ss_error ss_public_key_connect(secure_socket *sock, const char *host, int port, const ss_public_key *server_public_key) {
	if(!sock || !host || !server_public_key)
		return SS_ERROR_NULL_ARGUMENT;
	
	sock->their_public_keys = ss_malloc(sizeof server_public_key->value);

	if(!sock->their_public_keys)
		return SS_ERROR_OUT_OF_MEMORY;

	sock->their_public_key_count = 1;
	memcpy(sock->their_public_keys, server_public_key->value, sizeof server_public_key->value);
	return do_connect(sock, host, port);
}



ss_error ss_shared_key_listen(secure_socket *sock, int port, const ss_shared_key *shared_key) {
	if(!sock || !shared_key)
		return SS_ERROR_NULL_ARGUMENT;

	// TODO: state and provided_fields (check other functions too)
	memcpy(sock->shared_key, shared_key->value, sizeof sock->shared_key);
	return do_listen(sock, port);
}


ss_error ss_public_key_listen(secure_socket *sock, int port, const ss_public_key *client_public_keys, size_t key_count) {
	size_t key_len = sizeof client_public_keys->value;

	if(!sock || (!client_public_keys && key_count > 0))
		return SS_ERROR_NULL_ARGUMENT;

	if(key_count > 0) {
		sock->their_public_keys = ss_malloc(key_count * key_len);

		if(!sock->their_public_keys)
			return SS_ERROR_OUT_OF_MEMORY;

		sock->their_public_key_count = key_count;

		for(size_t i = 0; i < key_count; i++)
			memcpy(sock->their_public_keys + i * key_len, client_public_keys[i].value, key_len);
	}

	return do_listen(sock, port);
}



void ss_socket_free(secure_socket *sock) {
	if(!sock)
		return;

	ss_internal_close(sock->socket);

	ss_malloc_free(sock->their_public_keys);
	ss_malloc_free(sock->current_input_frame);

	ss_memset(sock, 0, sizeof *sock);
	ss_malloc_free(sock);
}


ss_error do_connect(secure_socket *sock, const char *host, int port) {
	int error;

	if(port < 1 || port > 65535)
		return SS_ERROR_INVALID_PORT;

	error = make_connection(sock, host, port);
	
	if(!error)
		error = perform_handshake(sock);

	return error;
}


ss_error make_connection(secure_socket *sock, const char *host, int port) {
	struct addrinfo *addr_result;
	// TODO: add hints like AI_ADDRCONFIG
	ss_error error = ss_getaddrinfo(host, NULL, NULL, &addr_result);

	if(error)
		return SS_ERROR_INVALID_HOSTNAME;

	while(addr_result) {
		sock->socket = ss_internal_socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
	
		if (sock->socket == -1)
			continue;

		if (ss_internal_connect(sock->socket, addr_result->ai_addr, addr_result->ai_addrlen) != -1)
			break;

		ss_internal_close(sock->socket);
		addr_result = addr_result->ai_next;
	}

	ss_freeaddrinfo(addr_result);
	return SS_SUCCESS;
}


ss_error perform_handshake(secure_socket *sock) {

	ss_error error = send_hello(sock);

	if(!error)
		error = receive_hello(sock);

	if(!error)
		error = send_finish(sock);

	if(!error)
		error = receive_finish(sock);

	return error;
}


ss_error do_listen(secure_socket *sock, int port) {
	ss_error error;

	if(port < 1 || port > 65535)
		return SS_ERROR_INVALID_PORT;

	// TODO

	return error;
}


secure_socket* ss_accept(secure_socket *server_sock) {
	ss_error error;
	secure_socket *sock;

	do {
		// accept

		if(!error)
			error = perform_handshake(sock);

		if(error)
			ss_internal_close(sock->socket);
	} while(error);

	return sock;
}


ss_error send_hello(secure_socket *sock) {
	// TODO: is setting length here necessary?
	sock->my_hello.header.length = pack_hello(sock->my_packed_hello, &sock->my_hello);
	ssize_t sent = ss_internal_send(sock->socket, sock->my_packed_hello, sock->my_hello.header.length, 0);

	if(sent <= 0)
		return SS_ERROR_DISCONNECT;
	
	return SS_SUCCESS;
}


ss_error receive_hello(secure_socket *sock) {
	const unsigned char *packed_ptr = sock->their_packed_hello;

	ss_error error = receive_message(sock, &packed_ptr, sizeof sock->their_packed_hello);

	if(error == SS_ERROR_BUFFER_TOO_SMALL)
		return SS_ERROR_INVALID_RESPONSE;
	else if(error)
		return error;
	
	return unpack_hello(&sock->their_hello, &packed_ptr, sock->their_packed_hello + sizeof sock->their_packed_hello);
}


ss_error send_finish(secure_socket *sock) {
	handshake_finish finish;
	unsigned char combined_hellos[sizeof sock->my_packed_hello + MAX_HELLO_LENGTH];

	generate_finish(&finish, combined_hellos, sock, sock->my_packed_hello, sock->my_hello.header.length, sock->their_packed_hello, sock->their_hello.header.length);

	// TODO: sign
	// TODO: send

	return SS_SUCCESS;
}


ss_error receive_finish(secure_socket *sock) {
	handshake_finish received_finish;
	handshake_finish expected_finish;
	unsigned char combined_hellos[sizeof sock->my_packed_hello + MAX_HELLO_LENGTH];

	generate_finish(&expected_finish, combined_hellos, sock, sock->their_packed_hello, sock->their_hello.header.length, sock->my_packed_hello, sock->my_hello.header.length);

	// TODO: receive
	// TODO: verify

	return SS_SUCCESS;
}


void generate_finish(handshake_finish *finish, unsigned char *combined_hellos, secure_socket *sock, unsigned char *first_hello, size_t first_hello_len, unsigned char *second_hello, size_t second_hello_len) {
	memcpy(combined_hellos, first_hello, first_hello_len);
	memcpy(combined_hellos + first_hello_len, second_hello, second_hello_len);

}


ss_error receive_exact(secure_socket *sock, unsigned char *buffer, size_t amount) {
	size_t total = 0;
	ssize_t read;

	assert(sock != NULL);
	assert(buffer != NULL);
	assert(amount > 0);

	while(total < amount) {
		read = ss_internal_recv(sock->socket, buffer, amount, MSG_WAITALL);

		if(read <= 0)
			return SS_ERROR_DISCONNECT;

		total += read;
	}

	return SS_SUCCESS;
}


ss_error receive_message(secure_socket *sock, unsigned char **buffer_ptr, size_t buffer_max) {
	uint32_t net_length, length;
	ss_error error;

	assert(sock != NULL);
	assert(buffer_ptr != NULL);
	assert(*buffer_ptr != NULL || (buffer_max == 0 && *buffer_ptr == NULL));
	assert(buffer_max == 0 || buffer_max >= MESSAGE_HEADER_LENGTH);

	error = receive_exact(sock, (unsigned char*)&net_length, sizeof net_length);

	if(error)
		return error;

	length = ntohl(net_length);

	if(length <= sizeof length)
		return SS_ERROR_INVALID_RESPONSE;

	// TODO: check for too large of a message?
	if(buffer_max > 0 && buffer_max < length)
		return SS_ERROR_BUFFER_TOO_SMALL;

	if(!*buffer_ptr) {
		*buffer_ptr = ss_malloc(length);
		if(!*buffer_ptr)
			return SS_ERROR_OUT_OF_MEMORY;
	}

	error = receive_exact(sock, *buffer_ptr + sizeof length, length - sizeof length);
	*((uint32_t*)*buffer_ptr) = net_length;

	if(error && buffer_max == 0) {
		ss_malloc_free(*buffer_ptr);
		*buffer_ptr = NULL;
		return error;
	}

	return SS_SUCCESS;
}

