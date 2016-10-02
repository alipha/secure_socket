#ifndef SS_IMPL_H
#define SS_IMPL_H

#include <stdint.h>


#define PROVIDED_VERSION					0x00000001U
#define PROVIDED_MIN_VERSION				0x00000002U
#define PROVIDED_SESSION_TOKEN_TIMEOUT		0x00000004U
#define PROVIDED_SESSION_TOKEN_LENGTH		0x00000008U
#define PROVIDED_SESSION_TOKEN				0x00000010U
#define PROVIDED_EPHEMERAL_KEY_LENGTH		0x00000020U
#define PROVIDED_EPHEMERAL_KEY_ID			0x00000040U
#define PROVIDED_EPHEMERAL_PUBLIC_KEY		0x00000080U
#define PROVIDED_MASTER_KEY_LENGTH			0x00000100U
#define PROVIDED_MASTER_PUBLIC_KEY 			0x00000200U
#define PROVIDED_NONCE_LENGTH				0x00000400U
#define PROVIDED_NONCE						0x00000800U
#define PROVIDED_SIGNATURE_LENGTH			0x00001000U
#define PROVIDED_TAG_LENGTH					0x00002000U
#define PROVIDED_SIGNATURE					0x40000000U
#define PROVIDED_TAG						0x80000000U

#define STATUS_GOOD							0x00000001U
#define STATUS_ERROR						0x00000002U
#define STATUS_UNKNOWN_STATUS				0x00000004U
#define STATUS_INVALID_LENGTH				0x00000008U
#define STATUS_VERSION_TOO_LOW				0x00000010U
#define STATUS_VERSION_TOO_HIGH				0x00000020U
#define STATUS_UNKNOWN_MESSAGE_TYPE			0x00000040U
#define STATUS_INVALID_SESSION_TOKEN_LENGTH	0x00000080U
#define STATUS_UNKNOWN_SESSION_TOKEN		0x00000100U
#define STATUS_INVALID_EPHEMERAL_KEY_LENGTH 0x00000200U
#define STATUS_INVALID_MASTER_KEY_LENGTH	0x00000400U
#define STATUS_INVALID_NONCE_LENGTH			0x00000800U
#define STATUS_INVALID_SIGNATURE_LENGTH		0x00001000U
#define STATUS_INVALID_TAG_LENGTH			0x00002000U
#define STATUS_INVALID_SIGNATURE			0x00004000U
#define STATUS_INVALID_TAG					0x00008000U
#define STATUS_UNKNOWN_MASTER_PUBLIC_KEY	0x00010000U
 
#define TOKEN_LENGTH 32U
#define PUBLIC_KEY_LENGTH 32U
#define SIGNATURE_LENGTH 32U
#define TAG_LENGTH 32U
#define NONCE_LENGTH 12U


typedef struct message_header {
	uint32_t length;
	uint32_t message_type;
	uint32_t status;
	uint32_t provided_fields;
} message_header;


typedef struct handshake_hello_body {
	message_header header;
	uint32_t version;
	uint32_t min_version;
	uint32_t token_timeout_seconds;
	uint32_t session_token_length;
	char session_token[TOKEN_LENGTH];
	uint32_t ephemeral_key_length;
	char ephemeral_public_key[PUBLIC_KEY_LENGTH];
	uint32_t master_key_length;
	char master_public_key[PUBLIC_KEY_LENGTH];
	uint32_t nonce_length;
	uint32_t signature_length;
	uint32_t tag_length;
} handshake_hello_body;

typedef struct handshake_hello {
	handshake_hello_body body;
	char signature[SIGNATURE_LENGTH];
	char tag[TAG_LENGTH];
} handshake_hello;


typedef struct handshake_finish {
	message_header header;
	char hello_tag[TAG_LENGTH];
} handshake_finish;


typedef struct message_frame {
	message_header header;
	char nonce[NONCE_LENGTH];
	uint32_t ephemeral_key_id;
	char new_ephemeral_public_key[PUBLIC_KEY_LENGTH];
	char ciphertext[1];
} message_frame;


#endif
