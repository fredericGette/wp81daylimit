# wp81daylimit

A Windows Phone 8.1 console utility that enforces a **daily screen-time limit** on a remote Windows PC by connecting over SSH, detecting the logged-in user, and initiating a shutdown once the allowed connection time has been exceeded.

![Example](Capture001.PNG)

---

## Overview

`wp81daylimit` runs on a Windows Phone 8.1 device and communicates with a remote Windows machine via a hand-rolled SSH client (no libssh2 dependency). It:

1. Checks whether the phone screen is locked and requests an unlock via the WinRT `Windows.Phone.System.SystemProtection` API. On Windows Phone 8.1, the networking stack is deactivated when the screen is locked, so the screen must be unlocked before any network connection can be established.
2. Connects to the remote host over TCP and performs a full SSH handshake (banner exchange, key exchange, password authentication). If the initial connect fails it retries for up to 10 seconds.
3. Opens an SSH channel and runs a PowerShell one-liner to enumerate logged-in users by inspecting running `explorer.exe` processes.
4. Checks whether a specific target user (`-t`) is currently logged in.
5. Appends a timestamped `0`/`1` entry to a daily log file, and deletes log files from previous days.
6. Counts the number of distinct 5-minute slots during which the user was logged in today.
7. If the cumulative connection time reaches or exceeds the configured limit (72 slots = 6 hours), it prints a warning.

---

## Usage

```
wp81daylimit [-p port] [-w password] [-t target_user] [user@]host
wp81daylimit [-p port] [-w password] [-t target_user] -u user host
```

### Options

| Flag | Description |
|---|---|
| `-p <port>` | SSH port on the remote host (default: `22`) |
| `-u <user>` | SSH username (alternative to `user@host` syntax) |
| `-w <password>` | SSH password (if omitted, prompted interactively with echo disabled) |
| `-t <target_user>` | **Required.** Windows username to monitor on the remote machine |
| `[user@]host` | Remote host, with optional inline username |

### Examples

```
# Prompt for password, monitor user "alice" on 192.168.1.10
wp81daylimit -t alice alice@192.168.1.10

# Non-default SSH port, password on command line
wp81daylimit -p 2222 -w s3cr3t -t alice -u alice 192.168.1.10
```

---

## Logging

Activity is recorded to daily plain-text log files stored on the phone at:

```
D:\Documents\wp81dailylimit\YYYY-MM-DD.log
```

Each line contains a timestamp and a boolean flag:

```
HH:MM  <0|1>
```

`1` means the target user was found logged in at that time; `0` means they were not. Log files from previous days are deleted automatically on each run.

---

## Deployment

- [Install a telnet server on the phone](https://github.com/fredericGette/wp81documentation/tree/main/telnetOverUsb#readme), in order to run the application.  
- Manually copy the executable from the root of this GitHub repository to the shared folder of the phone.
> [!NOTE]
> When you connect your phone with a USB cable, this folder is visible in the Explorer of your computer. And in the phone, this folder is mounted in `C:\Data\USERS\Public\Documents`
