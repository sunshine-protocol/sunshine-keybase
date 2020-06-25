#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Get the account id of the current device as String (if any)
 * Note: the device key must be in unlocked state otherwise `null` is returuned
 */
int32_t client_account_id(int64_t port);

/**
 * Check if the current client has a device key already or not
 */
int32_t client_has_device_key(int64_t port);

/**
 * Setup the Sunshine identity client using the provided path as the base path
 *
 * ### Safety
 * This assumes that the path is non-null c string.
 */
int32_t client_init(int64_t port, const char *path);

/**
 * Set a new Key for this device if not already exist.
 * you should call `client_has_device_key` first to see if you have already a key.
 *
 * suri is used for testing only.
 * phrase is used to restore a backup
 */
int32_t client_key_set(int64_t port, const char *suri, const char *password, const char *phrase);

int32_t error_message_utf8(char *buf, int32_t length);

int32_t last_error_length(void);
