#pragma once

/*
 * ssh_channel.h  -  SSH-2 connection protocol (RFC 4254)
 *
 * Implements:
 *   - Channel open ("session")
 *   - PTY request  (optional, for interactive shells)
 *   - Shell request
 *   - Interactive read/write loop using WaitForMultipleObjects on
 *     the socket (via WSAEventSelect) and stdin (HANDLE)
 *   - Window size adjustment (channel flow control)
 *   - Clean EOF and close handshake
 */

#include "ssh_client.h"

/*
 * Open a new "session" channel.
 * Populates s->local_channel, s->remote_channel, s->remote_window.
 * Returns 0 on success, -1 on error.
 */
int ssh_open_channel(SshSession *s);

/* Execute a single command and stream its output to stdout.
No stdin thread, no console mode fiddling.
Returns 0 on clean exit, -1 on error. */
int ssh_exec_loop(SshSession *s, const char *cmd, uint8_t **out_buf, size_t *out_len);
