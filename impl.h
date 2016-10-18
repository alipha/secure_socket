#ifndef SS_IMPL_H
#define SS_IMPL_H

#include "secure_socket.h"
#include <stdint.h>
#include <time.h>
#include <netdb.h>


#define PROVIDED_VERSION                    0x00000001U
#define PROVIDED_MIN_VERSION                0x00000002U
#define PROVIDED_SESSION_TOKEN_TIMEOUT      0x00000004U
#define PROVIDED_SESSION_TOKEN_LENGTH       0x00000008U
#define PROVIDED_SESSION_TOKEN              0x00000010U
#define PROVIDED_MESSAGE_ID                 0x00000020U
#define PROVIDED_EPHEMERAL_KEY_LENGTH       0x00000040U
#define PROVIDED_EPHEMERAL_KEY_ID           0x00000080U
#define PROVIDED_EPHEMERAL_PUBLIC_KEY       0x00000100U
#define PROVIDED_MASTER_KEY_LENGTH          0x00000200U
#define PROVIDED_MASTER_PUBLIC_KEY          0x00000400U
#define PROVIDED_MAX_MESSAGE_LENGTH         0x00000800U
#define PROVIDED_NONCE_LENGTH               0x00001000U
#define PROVIDED_NONCE                      0x00002000U
#define PROVIDED_SIGNATURE_LENGTH           0x00004000U
#define PROVIDED_TAG_LENGTH                 0x00008000U
#define PROVIDED_SIGNATURE                  0x40000000U
#define PROVIDED_TAG                        0x80000000U

#define STATUS_GOOD                         0x00000001U
#define STATUS_ERROR                        0x00000002U
#define STATUS_UNKNOWN_STATUS               0x00000004U
#define STATUS_INVALID_LENGTH               0x00000008U
#define STATUS_VERSION_TOO_LOW              0x00000010U
#define STATUS_VERSION_TOO_HIGH             0x00000020U
#define STATUS_UNKNOWN_MESSAGE_TYPE         0x00000040U
#define STATUS_INVALID_SESSION_TOKEN_LENGTH 0x00000080U
#define STATUS_UNKNOWN_SESSION_TOKEN        0x00000100U
#define STATUS_INVALID_EPHEMERAL_KEY_LENGTH 0x00000200U
#define STATUS_INVALID_MASTER_KEY_LENGTH    0x00000400U
#define STATUS_INVALID_MAX_MESSAGE_LENGTH   0x00000800U
#define STATUS_INVALID_NONCE_LENGTH         0x00001000U
#define STATUS_INVALID_SIGNATURE_LENGTH     0x00002000U
#define STATUS_INVALID_TAG_LENGTH           0x00004000U
#define STATUS_INVALID_SIGNATURE            0x00008000U
#define STATUS_INVALID_MASTER_KEY_TAG       0x00010000U
#define STATUS_INVALID_TAG                  0x00020000U
#define STATUS_INVALID_NONCE                0x00040000U
#define STATUS_UNKNOWN_MASTER_PUBLIC_KEY    0x00080000U

#define MESSAGE_HEADER_LENGTH               (4 * sizeof(uint32_t))
#define MAX_HELLO_LENGTH                    10000U
#define COMBINED_KEY_LENGTH					(SS_PUBLIC_KEY_LENGTH + SS_PRIVATE_KEY_LENGTH) 
#define EPHEMERAL_PUBLIC_KEY_LENGTH         32U
#define EPHEMERAL_PRIVATE_KEY_LENGTH        32U
#define TOKEN_LENGTH                        32U
#define SIGNATURE_LENGTH                    64U
#define TAG_LENGTH                          16U
#define NONCE_LENGTH                        8U

#define STATE_INIT                          0x00000001U
#define STATE_HAS_MASTER_KEY                0x00000002U
#define STATE_HAS_SOCKET                    0x00000004U
#define STATE_HAS_BIND                      0x00000008U
#define STATE_CONNECTED                     0x00000010U
#define STATE_SENT_HELLO                    0x00000020U
#define STATE_RECEIVED_HELLO                0x00000040U
#define STATE_SENT_FINISH                   0x00000080U
#define STATE_RECEIVED_FINISH               0x00000100U
#define STATE_START_NEW_EPHEMERAL_KEY       0x00000200U
#define STATE_RECEIVED_NEW_EPHEMERAL_KEY    0x00000400U

#define MESSAGE_TYPE_HELLO                  1
#define MESSAGE_TYPE_FINISH                 2
#define MESSAGE_TYPE_DATA                   3
#define MESSAGE_TYPE_PROOF_OF_WORK          4



typedef struct message_header {
	uint32_t length;
	uint32_t message_type;
	uint32_t status;
	uint32_t provided_fields;
} message_header;


typedef struct handshake_hello {
	message_header header;
	uint32_t version;
	uint32_t min_version;
// TODO: client proof of work fields
	uint32_t token_timeout_seconds;
	uint32_t session_token_length;
	char session_token[TOKEN_LENGTH];
	uint32_t ephemeral_key_length;
	char ephemeral_public_key[EPHEMERAL_PUBLIC_KEY_LENGTH];
	uint32_t master_key_length;
	char master_public_key[SS_PUBLIC_KEY_LENGTH];
	uint32_t max_message_length;
	uint32_t nonce_length;
	uint32_t signature_length;
	uint32_t tag_length;
} handshake_hello;


typedef struct handshake_finish {
	message_header header;
	char master_key_signature[SIGNATURE_LENGTH];
	char master_symmetric_key_tag[TAG_LENGTH];
	char ephemeral_key_tag[TAG_LENGTH];
} handshake_finish;


typedef struct message_frame {
	message_header header;
	uint32_t message_id;
	char nonce[NONCE_LENGTH];	// client starts even, server starts odd, increment by 2
	uint32_t ephemeral_key_id;
	char new_ephemeral_public_key[EPHEMERAL_PUBLIC_KEY_LENGTH];
	char ciphertext[1];
} message_frame;


struct secure_socket {
	int socket;
	uint32_t state;
	time_t connected_time;
	handshake_hello my_hello;
	handshake_hello their_hello;
	unsigned char my_packed_hello[sizeof(handshake_hello)]; // TODO: calculate exact size?
	unsigned char their_packed_hello[MAX_HELLO_LENGTH];
	unsigned char shared_key[SS_SHARED_KEY_LENGTH];
	unsigned char master_private_key[SS_PRIVATE_KEY_LENGTH];
	unsigned char *their_public_keys;
	size_t their_public_key_count;
	unsigned char ephemeral_private_key[EPHEMERAL_PRIVATE_KEY_LENGTH];
	unsigned char my_nonce[NONCE_LENGTH];
	unsigned char their_nonce[NONCE_LENGTH];
	uint32_t ephemeral_key_id;
	time_t ephemeral_key_creation_time;
	uint32_t ephemeral_key_message_count;
	uint32_t ephemeral_key_byte_count;
	unsigned char my_new_ephemeral_public_key[EPHEMERAL_PUBLIC_KEY_LENGTH];
	unsigned char my_new_ephemeral_private_key[EPHEMERAL_PRIVATE_KEY_LENGTH];
	unsigned char their_new_ephemeral_public_key[EPHEMERAL_PUBLIC_KEY_LENGTH];
	uint32_t bytes_read;
	message_frame *current_input_frame;
};


extern void (*ss_random)(void * const buf, const size_t size);
extern int (*ss_sign_keypair)(unsigned char *, unsigned char *);

extern void* (* volatile ss_memset)(void *, int, size_t);

extern void* (*ss_malloc)(size_t);
extern void (*ss_malloc_free)(void *);

extern int (*ss_internal_close)(int);
extern int (*ss_internal_socket)(int, int, int);
extern int (*ss_internal_connect)(int, const struct sockaddr *, socklen_t);

extern ssize_t (*ss_internal_send)(int, const void *, size_t, int);
extern ssize_t (*ss_internal_recv)(int, void *, size_t, int);

extern int (*ss_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo**);
extern void (*ss_freeaddrinfo)(struct addrinfo *);



void ss_sign_message(unsigned char *signature, const void *message, size_t message_len, const ss_key_pair *key_pair);
BOOL ss_verify_signature(const unsigned char *signature, const void *message, size_t message_len, ss_public_key *public_key);

void increment_nonce_by_2(unsigned char *nonce);

void binary_write(unsigned char **output, const void *input, size_t amount);
BOOL binary_read(void *output, const unsigned char **input, const unsigned char *end_ptr, size_t amount);
void uint32_write(unsigned char **output, uint32_t value);
BOOL uint32_read(uint32_t *value, const unsigned char **input, const unsigned char *end_ptr);

size_t pack_header(unsigned char *output, const message_header *header);
ss_error unpack_header(message_header *header, const unsigned char **input);

size_t pack_hello(unsigned char *output, const handshake_hello *hello);
ss_error unpack_hello(handshake_hello *hello, const unsigned char **input, const unsigned char *end_ptr);

size_t pack_finish(unsigned char *output, const handshake_finish *finish);
ss_error unpack_finish(handshake_finish *finish, const unsigned char **input);

#endif
