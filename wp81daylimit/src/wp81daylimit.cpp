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

#include <roapi.h>
#include <winstring.h>
#include <wrl/client.h>   // Microsoft::WRL::ComPtr

// ── ABI GUIDs from Windows_Phone_System.idl ────────────────────────────────
// {49C36560-97E1-4D99-8BFB-BEFEAA6ACE6D}  ISystemProtectionStatics
static const IID IID_ISystemProtectionStatics = {
    0x49C36560, 0x97E1, 0x4D99,
    { 0x8B, 0xFB, 0xBE, 0xFE, 0xAA, 0x6A, 0xCE, 0x6D }
};
// {0692FA3F-8F11-4C4B-AA0D-87D7AF7B1779}  ISystemProtectionUnlockStatics
static const IID IID_ISystemProtectionUnlockStatics = {
    0x0692FA3F, 0x8F11, 0x4C4B,
    { 0xAA, 0x0D, 0x87, 0xD7, 0xAF, 0x7B, 0x17, 0x79 }
};

// ── Minimal vtable-only interface declarations ──────────────────────────────
// (avoids dependency on the generated WinRT header for these phone-specific
//  interfaces, which may not ship in the WP8.1 SDK include path)

MIDL_INTERFACE("49C36560-97E1-4D99-8BFB-BEFEAA6ACE6D")
ISystemProtectionStatics : public IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE get_ScreenLocked(boolean *value) = 0;
};

MIDL_INTERFACE("0692FA3F-8F11-4C4B-AA0D-87D7AF7B1779")
ISystemProtectionUnlockStatics : public IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE RequestScreenUnlock() = 0;
};

// ── Helper ──────────────────────────────────────────────────────────────────
// Returns:
//   0  – screen was not locked (or lock-state could not be determined)
//   1  – screen was locked; RequestScreenUnlock() was called
//  -1  – hard error (RoInitialize / activation failed)
static int check_and_unlock_screen(void)
{
    HRESULT hr;

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr) && hr != S_FALSE && hr != 0x80010106) {
        fprintf(stderr, "[screen] RoInitialize failed: 0x%08X\n", (unsigned)hr);
        return -1;
    }

    static const wchar_t kClassName[] =
        L"Windows.Phone.System.SystemProtection";

    HSTRING hClassName = NULL;
    hr = WindowsCreateString(kClassName,
                             (UINT32)(sizeof(kClassName) / sizeof(wchar_t) - 1),
                             &hClassName);
    if (FAILED(hr)) {
        fprintf(stderr, "[screen] WindowsCreateString failed: 0x%08X\n", (unsigned)hr);
        RoUninitialize();
        return -1;
    }

    // ── Nested scope: all ComPtrs destroyed here, before RoUninitialize ────
    int result = 0;
    {
        Microsoft::WRL::ComPtr<ISystemProtectionStatics> pStatics;
		Microsoft::WRL::ComPtr<ISystemProtectionUnlockStatics> pUnlockStatics;
		boolean locked = false;
		DWORD deadline;

        hr = RoGetActivationFactory(hClassName,
                                    IID_ISystemProtectionStatics,
                                    (void **)pStatics.GetAddressOf());
        if (FAILED(hr)) {
            fprintf(stderr, "[screen] RoGetActivationFactory(ISystemProtectionStatics)"
                            " failed: 0x%08X\n", (unsigned)hr);
            result = -1;
            goto cleanup;
        }

        hr = pStatics->get_ScreenLocked(&locked);
        if (FAILED(hr)) {
            fprintf(stderr, "[screen] get_ScreenLocked failed: 0x%08X\n", (unsigned)hr);
            result = -1;
            goto cleanup;
        }

        if (!locked) {
            fprintf(stderr, "[screen] screen is not locked\n");
            goto cleanup;
        }

        fprintf(stderr, "[screen] screen is locked - requesting unlock\n");

        hr = RoGetActivationFactory(hClassName,
                                    IID_ISystemProtectionUnlockStatics,
                                    (void **)pUnlockStatics.GetAddressOf());
        if (FAILED(hr)) {
            fprintf(stderr, "[screen] RoGetActivationFactory(ISystemProtectionUnlockStatics)"
                            " failed: 0x%08X\n", (unsigned)hr);
            result = -1;
            goto cleanup;
        }

		deadline = GetTickCount() + 5000;
		do {
			hr = pUnlockStatics->RequestScreenUnlock();
			if (SUCCEEDED(hr)) break;
			if (hr != HRESULT_FROM_WIN32(EPT_S_NOT_REGISTERED)) break; /* non-transient */
			Sleep(200);
		} while (GetTickCount() < deadline);

		if (FAILED(hr)) {
			fprintf(stderr, "[screen] RequestScreenUnlock failed: 0x%08X\n", (unsigned)hr);
		 	result = -1;
        } else {
            result = 1;
        }

    cleanup:;
        // pStatics and pUnlockStatics Release() here, inside the WinRT apartment
    }
    // ── ComPtrs are gone; now safe to tear down the apartment ──────────────

    WindowsDeleteString(hClassName);
    RoUninitialize();
    return result;
}

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

	// ── Screen-unlock check ──────────────────────────────────────────
    check_and_unlock_screen();
    // We proceed regardless of the return value: the SSH session is useful
    // even when unlock fails (e.g. wrong apartment, locked by policy, etc.).
    // 

	memset(password, 0, sizeof(password));
	if (opt_password) {
		_snprintf_s(password, sizeof(password), _TRUNCATE, "%s", opt_password);
	}
	else {
		char prompt[128];
		_snprintf_s(prompt, sizeof(prompt), _TRUNCATE, "%s@%s's password: ", opt_user, opt_host);
		if (read_password(prompt, password, sizeof(password)) != 0) {
			fprintf(stderr, "[main] failed to read password\n");
			return 1;
		}
	}

	memset(&s, 0, sizeof(s));
	s.fd = ssh_tcp_connect(opt_host, opt_port);
	if (s.fd < 0) {
		fprintf(stderr, "[main] TCP connect failed : %s:%d\n", opt_host, opt_port);

		return 1;
	}
	if (ssh_banner_exchange(&s) != 0) {
		fprintf(stderr, "[main] banner failed\n");
		goto fail;
	}
	if (ssh_kex(&s) != 0) {
		fprintf(stderr, "[main] kex failed\n");
		goto fail;
	}
	if (ssh_userauth_password(&s, opt_user, password) != 0) {
		fprintf(stderr, "[main] password auth failed\n");
		goto fail;
	}
	SecureZeroMemory(password, sizeof(password));

	if (ssh_open_channel(&s) != 0) {
		fprintf(stderr, "[main] channel failed\n");
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
			fprintf(stderr, "exec command failed\n");
		}

		check_logged_user(opt_target_user, out_buf, &out_len);
		free(out_buf);
	}

	if (count_true_slots(5) >= 72) {
		printf("User %s connected at least during %d hours.\n", opt_target_user, 5 * 72 / 60);
	}

	if (s.fd >= 0) ssh_disconnect(&s, "session ended");
	return 0;

fail:
	SecureZeroMemory(password, sizeof(password));
	if (s.fd >= 0) ssh_disconnect(&s, "fatal error");
	return 1;
}

