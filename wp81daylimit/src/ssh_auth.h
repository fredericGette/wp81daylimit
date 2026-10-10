#pragma once

/*
 * ssh_auth.h  -  SSH-2 user authentication (RFC 4252)
 *
 * Implements:
 *   - Service request: "ssh-userauth"
 *   - Method: "password"
 *
 * No pubkey, no keyboard-interactive.
 */

#include "ssh_client.h"

/*
 * Authenticate with username + password.
 *
 * Sends SSH_MSG_SERVICE_REQUEST("ssh-userauth"), waits for SERVICE_ACCEPT,
 * then sends SSH_MSG_USERAUTH_REQUEST with method "password".
 *
 * Handles SSH_MSG_USERAUTH_BANNER (prints to stderr and retries).
 *
 * Returns  0 on SSH_MSG_USERAUTH_SUCCESS.
 * Returns -1 on SSH_MSG_USERAUTH_FAILURE or any protocol error.
 */
int ssh_userauth_password(SshSession *s,
                          const char *username,
                          const char *password);
