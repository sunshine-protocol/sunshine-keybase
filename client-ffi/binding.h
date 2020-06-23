#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CLIENT_BAD_CSTR 1

#define CLIENT_IPFS_CONFIG_ERR 3

#define CLIENT_IPFS_STORE_ERR 4

#define CLIENT_OK 0

#define CLIENT_SUBXT_CREATE_ERR 2

#define CLIENT_UNKNOWN -1

int32_t error_message_utf8(char *buf, int32_t length);

/**
 * Setup the Sunshine identity client using the provided path as the base path
 *
 * ### Safety
 * This assumes that the path is non-null c string.
 */
int32_t init_client(int64_t port, const char *path);

int32_t last_error_length(void);
