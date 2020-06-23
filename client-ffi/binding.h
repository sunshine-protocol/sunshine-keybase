#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CLIENT_BAD_CSTR 1

#define CLIENT_HAS_DEVICE_KEY 6

#define CLIENT_IPFS_CONFIG_ERR 3

#define CLIENT_IPFS_STORE_ERR 4

#define CLIENT_OK 0

#define CLIENT_PASSWORD_TOO_SHORT 7

#define CLIENT_SUBXT_CREATE_ERR 2

#define CLIENT_UNINIT 5

#define CLIENT_UNKNOWN -1

/**
 * Setup the Sunshine identity client using the provided path as the base path
 *
 * ### Safety
 * This assumes that the path is non-null c string.
 */
int32_t client_init(int64_t port, const char *path);

/**
 * Set a new Key for this device if not already exist.
 *
 * suri is used for testing only.
 *
 * ### Safety
 * Suri coud be null for indicating that we don't have to use it
 */
int32_t client_key_set(int64_t port, const char *suri);

int32_t error_message_utf8(char *buf, int32_t length);

int32_t last_error_length(void);
