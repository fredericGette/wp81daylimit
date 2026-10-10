#pragma once

#include <windows.h>
#include <stdint.h>

BOOL check_logged_user(const char *target, uint8_t *out_buf, size_t *out_len);

int count_true_slots(const int slot_minute);