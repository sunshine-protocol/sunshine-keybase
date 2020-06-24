#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Check if the current client has a device key already or not
 */
void client_has_device_key(int64_t port);

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
 * suri could be empty string for indicating that we don't have to use it
 * phrase could be emoty string for indicating that we don't have to create a device key from it.
 */
int32_t client_key_set(int64_t port, const char *suri, const char *password, const char *phrase);

int32_t error_message_utf8(char *buf, int32_t length);

int32_t last_error_length(void);
