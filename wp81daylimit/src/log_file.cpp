
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    

#include "log_file.h"
#include "Win32Api.h"

/* -----------------------------------------------------------------------
* Configuration
* --------------------------------------------------------------------- */
/* Directory that holds the log files, with trailing backslash.
* Change to an absolute path if needed, e.g. "C:\\Logs\\" */
#define LOG_DIR  "D:\\Documents\\wp81dailylimit\\"

/* Extension used for log files */
#define LOG_EXT  ".log"

/*
* build_today_log_path()
*
* Builds the full path of the log file for the current day.
* The filename stem is the local date formatted as "YYYY-MM-DD",
* placed in LOG_DIR with the LOG_EXT extension.
*
* Example result: ".\2026-05-27.log"
*
* Parameters:
*   buf      - output buffer that receives the null-terminated path.
*   buf_size - size of buf in bytes; should be at least MAX_PATH.
*   st       - current local time, as returned by GetLocalTime().
*
* Returns:
*   TRUE  on success.
*   FALSE if the buffer is too small to hold the result.
*/
static BOOL build_today_log_path(char *buf, size_t buf_size, const SYSTEMTIME *st)
{
	int ret = _snprintf_s(buf, buf_size, _TRUNCATE,
		"%s%04u-%02u-%02u%s",
		LOG_DIR,
		(unsigned)st->wYear,
		(unsigned)st->wMonth,
		(unsigned)st->wDay,
		LOG_EXT);
	return (ret > 0);
}


/*
* delete_old_logs()
*
* Deletes every file matching *LOG_EXT in LOG_DIR whose full filename
* differs from today's log file.
*
* Parameters:
*   today_log_path - full path of today's log file, as returned by
*                    build_today_log_path(). Used to extract the expected
*                    filename and skip deletion of the current day's file.
*/
static void delete_old_logs(const char *today_log_path)
{
	WIN32_FIND_DATAA fd;
	HANDLE           hFind;
	char             pattern[MAX_PATH];
	char             filepath[MAX_PATH];
	const char      *today_filename;

	/* Extract just the filename part of today_log_path, e.g. "2026-05-27.log" */
	today_filename = strrchr(today_log_path, '\\');
	if (today_filename != NULL)
		today_filename++;           /* skip the backslash */
	else
		today_filename = today_log_path;   /* no directory component */

	_snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s*%s", LOG_DIR, LOG_EXT);

	hFind = FindFirstFileA(pattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do {
		if (strcmp(fd.cFileName, today_filename) != 0)
		{
			_snprintf_s(filepath, sizeof(filepath), _TRUNCATE,
				"%s%s", LOG_DIR, fd.cFileName);
			DeleteFileA(filepath);
		}
	} while (FindNextFileA(hFind, &fd));

	FindClose(hFind);
}

/* -----------------------------------------------------------------------
* Append one timestamped line to today's log file.
* Creates the file if it doesn't exist (fopen "a" mode).
* --------------------------------------------------------------------- */
static BOOL append_log_entry(const char *filepath,
	const SYSTEMTIME *st,
	BOOL value)
{
	FILE *f = NULL;
	errno_t err = fopen_s(&f, filepath, "a");
	if (err != 0 || !f)
		return FALSE;

	fprintf(f, "%02u:%02u  %d\n",
		(unsigned)st->wHour,
		(unsigned)st->wMinute,
		value ? 1 : 0);

	fclose(f);
	return TRUE;
}

/*
* check_logged_user
*
* Parses the CSV output of the PowerShell command:
*
*   Get-Process -Name explorer -IncludeUserName |
*   Select-Object UserName, Id |
*   ConvertTo-Csv -NoTypeInformation
*
* Expected output format (CRLF line endings):
*
*   "UserName","Id"\r\n
*   "DOMAIN\User","PID"\r\n
*   ...
*
* Parameters:
*   target   - substring to match against each CSV row (typically a username
*              or domain\username fragment).
*   out_buf  - pointer to the raw output buffer; modified in place by
*              strtok_s() (NUL bytes are written at delimiter positions).
*   out_len  - length of the raw output buffer
*
*
*/
BOOL check_logged_user(const char *target, uint8_t *out_buf, size_t *out_len)
{
	SYSTEMTIME st;
	char log_path[MAX_PATH];

	/* 1. Get current local time once � use the same snapshot throughout */
	GetLocalTime(&st);

	/* 2. Build today's filename stem */
	if (!build_today_log_path(log_path, sizeof(log_path), &st))
		return 1;

	/* 3. Delete stale log files */
	delete_old_logs(log_path);

	/* 4. Sample the boolean value */
	BOOL found = FALSE;
	if (*out_len > 0)
	{
		/* Skip the header line ("UserName","Id"), then parse data rows */
		char *context = NULL;                      /* strtok_s state � must be NULL on first call */
		char *line = strtok_s((char *)out_buf, "\n", &context);
		int   header_skipped = 0;

		while (line) {
			/* Strip trailing \r left by CRLF line endings. */
			size_t ll = strlen(line);
			if (ll > 0 && line[ll - 1] == '\r') line[ll - 1] = '\0';

			/* Always skip the header row ("UserName","Id") on the first iteration. */
			if (!header_skipped) {
				header_skipped = 1;
				line = strtok_s(NULL, "\n", &context);
				continue;
			}

			/* CSV data row */
			if (strstr(line, target)) {
				char username[64] = { 0 };
				int  pid = 0;

				/* Strip the surrounding quotes and comma: "USER","PID" */
				if (sscanf_s(line, "\"%63[^\"]\",%*[\"]%d", username, (unsigned)sizeof(username), &pid) == 2) {
					printf("Found target user (UserName,PID) : (%s,%d)\n", username, pid);
					found = TRUE;
				}
			}
			line = strtok_s(NULL, "\n", &context);
		}
	}

	if (!found)
	{
		printf("Target user not found in output.");
	}


	/* 5. Append the entry (creates file on first run of the day) */
	if (!append_log_entry(log_path, &st, found))
	{
		return -1;
	}

	return 0;
}


/*
*
* Counts the number of distinct time slots during which a boolean value
* was TRUE, as recorded in a daily log file.
*
* Log file format (one entry per line):
*   HH:MM <0|1>
* where HH:MM is the local time and <0|1> is the boolean value.
* Lines that do not match this format are silently skipped.
* FALSE entries (value 0) are ignored entirely.
*
*
* Example with slot_minute = 5:
*   10:10 1  -> slot 1 opened, anchor = 10:10
*   10:13 0  -> ignored
*   10:14 1  -> 4 min from anchor, still slot 1
*   10:18 1  -> 8 min from anchor, slot 2 opened, anchor = 10:18
*   Result: 2
*
* Parameters:
*   slot_minute  - slot width in minutes; a TRUE entry that is at least
*                  this many minutes from the current slot anchor opens
*                  a new slot. Must be > 0.
*
* Returns:
*   Number of distinct TRUE slots (>= 0) on success.
*   -1 if the file could not be opened.
*/
int count_true_slots(const int slot_minute)
{
	FILE       *f = NULL;
	errno_t     err;
	char        line[32];
	int         slot_count = 0;
	BOOL        in_run = FALSE;
	WORD        slot_hour = 0;   /* timestamp of the first TRUE of the current slot */
	WORD        slot_min = 0;
	SYSTEMTIME st;
	char       log_path[MAX_PATH];

	GetLocalTime(&st);

	if (!build_today_log_path(log_path, sizeof(log_path), &st))
		return -1;

	err = fopen_s(&f, log_path, "r");
	if (err != 0 || !f)
		return -1;

	while (fgets(line, sizeof(line), f) != NULL)
	{
		WORD cur_hour = 0;
		WORD cur_min = 0;
		int  val = 0;
		int  fields;
		int  delta_min;

		/* Expected format: "HH:MM <0|1>" */
		fields = sscanf_s(line, "%2hu:%2hu %d",
			&cur_hour, &cur_min, &val);

		if (fields != 3 || !val)
			continue;

		/* TRUE entry */
		if (!in_run)
		{
			/* First TRUE ever, or first after a long gap: open a new slot */
			slot_count++;
			in_run = TRUE;
			slot_hour = cur_hour;
			slot_min = cur_min;
		}
		else
		{
			/* Measure gap from the anchor of the current slot, not from prev TRUE */
			delta_min = (int)cur_hour * 60 + (int)cur_min
				- (int)slot_hour * 60 - (int)slot_min;

			if (delta_min >= slot_minute)
			{
				/* Beyond the slot_minute(example: 5 minutes) window: this TRUE opens a new slot */
				slot_count++;
				slot_hour = cur_hour;
				slot_min = cur_min;
				/* in_run stays TRUE */
			}
			/* else: still within the same slot_minute slot, nothing changes */
		}
	}

	fclose(f);
	return slot_count;
}
