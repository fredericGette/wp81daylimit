// wp81dailylimit.cpp : Defines the entry point for the console application.
//
// Context: 
// win32 console application, 
// linked with Msvcr110.dll, 
// architecture ARM 32bit little endian. 
// Use secure functions when possible (example _snprintf_s instead of _snprintf)

#include "stdafx.h"

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0603
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssh_client.h"
#include "ssh_transport.h"
#include "ssh_kex.h"
#include "ssh_auth.h"
#include "ssh_channel.h"
#include "log_file.h"
#include "Win32Api.h"
#include "EtwLogger.h"

static const GUID kProviderGuid = { /* 14cbde36-bfed-4c49-8319-db0679011d86 */
	0x14cbde36,
	0xbfed,
	0x4c49,
	{ 0x83, 0x19, 0xdb, 0x06, 0x79, 0x01, 0x1d, 0x86 }
};

static int read_password(const char *prompt, char *buf, size_t buf_size)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD  mode = 0;
	size_t len;

	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	if (!fgets(buf, (int)buf_size, stdin)) {
		SetConsoleMode(hStdin, mode);
		return -1;
	}
	SetConsoleMode(hStdin, mode);
	fprintf(stderr, "\n");

	len = strlen(buf);
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = '\0';
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-p port] [-w password] [-t target_user] [user@]host\n"
		"       %s [-p port] [-w password] [-t target_user] -u user host\n",
		prog, prog);
}

int main(int argc, char *argv[])
{
	const char *opt_user = NULL;
	const char *opt_host = NULL;
	const char *opt_password = NULL;
	const char *opt_target_user = NULL;
	uint16_t    opt_port = 22;
	char        password[256];
	SshSession  s;
	int         i;

	EtwLogger::Init(kProviderGuid);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			long p = strtol(argv[++i], NULL, 10);
			if (p < 1 || p > 65535) {
				fprintf(stderr, "Invalid port\n");
				return 1;
			}
			opt_port = (uint16_t)p;
		}
		else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
			opt_user = argv[++i];
		}
		else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
			opt_password = argv[++i];
		}
		else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
			opt_target_user = argv[++i];
		}
		else if (argv[i][0] != '-') {
			char *at = strchr(argv[i], '@');
			if (at) { *at = '\0'; opt_user = argv[i]; opt_host = at + 1; }
			else { opt_host = argv[i]; }
		}
		else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	if (!opt_host) { usage(argv[0]); return 1; }
	if (!opt_target_user) {
		fprintf(stderr, "Target user (-t) is required\n");
		usage(argv[0]);
		return 1;
	}

	memset(password, 0, sizeof(password));
	if (opt_password) {
		_snprintf_s(password, sizeof(password), _TRUNCATE, "%s", opt_password);
	}
	else {
		char prompt[128];
		_snprintf_s(prompt, sizeof(prompt), _TRUNCATE, "%s@%s's password: ", opt_user, opt_host);
		if (read_password(prompt, password, sizeof(password)) != 0) {
			fprintf(stderr, "[main] failed to read password\n");
			EtwLogger::Cleanup();
			return 1;
		}
	}

	memset(&s, 0, sizeof(s));
	s.fd = ssh_tcp_connect(opt_host, opt_port);
	if (s.fd < 0) {
		fprintf(stderr, "[main] TCP connect failed\n");
		EtwLogger::LogEvent(TRACE_LEVEL_FATAL, L"TCP connect failed : %S:%d", opt_host, opt_port);
		return 1;
	}
	if (ssh_banner_exchange(&s) != 0) {
		fprintf(stderr, "[main] banner failed\n");
		EtwLogger::LogEvent(TRACE_LEVEL_FATAL, L"SSH banner failed");
		goto fail;
	}
	if (ssh_kex(&s) != 0) {
		fprintf(stderr, "[main] kex failed\n");
		EtwLogger::LogEvent(TRACE_LEVEL_FATAL, L"SSH kex failed");
		goto fail;
	}
	if (ssh_userauth_password(&s, opt_user, password) != 0) {
		fprintf(stderr, "[main] auth failed\n");
		EtwLogger::LogEvent(TRACE_LEVEL_FATAL, L"Password auth failed");
		goto fail;
	}
	SecureZeroMemory(password, sizeof(password));

	if (ssh_open_channel(&s) != 0) {
		fprintf(stderr, "[main] channel failed\n");
		EtwLogger::LogEvent(TRACE_LEVEL_FATAL, L"SSH open channel failed");
		goto fail;
	}

	{
		const char *cmd = "powershell -Command \""
			"Get-Process -Name explorer -IncludeUserName"
			" | Select-Object UserName, Id"
			" | ConvertTo-Csv -NoTypeInformation\"";
		uint8_t *out_buf = NULL;
		size_t   out_len = 0;

		if (ssh_exec_loop(&s, cmd, &out_buf, &out_len) != 0) {
			fprintf(stderr, "exec failed\n");
			EtwLogger::LogEvent(TRACE_LEVEL_ERROR, L"SSH exec command failed.");
		}

		check_logged_user(opt_target_user, out_buf, &out_len);
		free(out_buf);
	}

	if (count_true_slots(5) >= 72) {
		EtwLogger::LogEvent(TRACE_LEVEL_INFORMATION, L"User %S connected at least during %d hours.", opt_target_user, 5 * 72 / 60);
	}

	if (s.fd >= 0) ssh_disconnect(&s, "session ended");
	EtwLogger::Cleanup();
	return 0;

fail:
	SecureZeroMemory(password, sizeof(password));
	if (s.fd >= 0) ssh_disconnect(&s, "fatal error");
	EtwLogger::Cleanup();
	return 1;
}

