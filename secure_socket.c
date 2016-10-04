#include "secure_socket.h"
#include <string.h>
#include <sodium.h>


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


