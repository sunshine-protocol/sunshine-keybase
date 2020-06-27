#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CLIENT_ALREADY_INIT 8

#define CLIENT_BAD_CSTR 2

#define CLIENT_BAD_MNEMONIC 12

#define CLIENT_BAD_SURI 11

#define CLIENT_BAD_UID 13

#define CLIENT_FAIL_TO_LOCK 14

#define CLIENT_FAIL_TO_UNLOCK 16

#define CLIENT_HAS_DEVICE_KEY 9

#define CLIENT_IPFS_CONFIG_ERR 4

#define CLIENT_IPFS_STORE_ERR 6

#define CLIENT_KEYSTORE_OPEN_ERR 5

#define CLIENT_LOCKED_OK 15

#define CLIENT_OK 1

#define CLIENT_PASSWORD_TOO_SHORT 10

#define CLIENT_SUBXT_CREATE_ERR 3

#define CLIENT_UNINIT 7

#define CLIENT_UNKNOWN -1

#define CLIENT_UNKNOWN_SERVICE 18

#define CLIENT_UNLOCKED_OK 17

/**
 * Add new paperkey from the current account
 */
int32_t client_add_paperkey(int64_t port);

/**
 * Check if the current client has a device key already or not
 */
int32_t client_has_device_key(int64_t port);

/**
 * Get the a list that contains all the client identity data
 */
int32_t client_identity(int64_t port, const char *uid);

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

/**
 * Lock the client
 */
int32_t client_lock(int64_t port);

/**
 * Prove the account identity for the provided service and there id
 *
 * Current Avalibale Services
 * Github = 1
 */
int32_t client_prove_identity(int64_t port, int32_t service, const char *id);

/**
 * Get the UID of identifier as String (if any)
 */
int32_t client_resolve_uid(int64_t port, const char *identifier);

/**
 * Get account id
 */
int32_t client_signer_account_id(int64_t port);

/**
 * UnLock the client
 */
int32_t client_unlock(int64_t port, const char *password);

int32_t error_message_utf8(char *buf, int32_t length);

int32_t last_error_length(void);
