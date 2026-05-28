#include "EtwLogger.h"
#include <stdarg.h>   // va_list, va_start, va_end
#include <wchar.h>    // vswprintf_s, wcslen
#include <stdlib.h> 

namespace EtwLogger
{
	// Hidden inside the namespace and cpp file, preventing global scope pollution
	static REGHANDLE g_hProvider = 0;

	void Init(const GUID& providerId)
	{
		// Only register if we haven't already
		if (g_hProvider == 0) {
			EventRegister(&providerId, nullptr, nullptr, &g_hProvider);
		}
	}

	void Cleanup()
	{
		if (g_hProvider) {
			EventUnregister(g_hProvider);
			g_hProvider = 0;
		}
	}

	void LogEvent(UCHAR level, const wchar_t* fmt, ...)
	{
		// Fail gracefully if not initialized or if format string is null
		if (!g_hProvider || !fmt) return;

		// Format the message into a fixed-size stack buffer.
		// _TRUNCATE makes vswprintf_s silently truncate rather than invoke the
		// invalid-parameter handler — important for Msvcr110 on ARM where the
		// default handler calls abort().
		wchar_t buf[512];
		va_list args;
		va_start(args, fmt);
		vswprintf_s(buf, _countof(buf), fmt, args);
		va_end(args);

		// Build the ETW event descriptor
		EVENT_DESCRIPTOR desc;
		EventDescCreate(&desc,
			1,      // EventId
			0,      // Version
			0,      // Channel
			level,  // Level
			0,      // Task
			0,      // Opcode
			0);     // Keyword

					// Pack the formatted string as a single ETW data descriptor
		EVENT_DATA_DESCRIPTOR data;
		EventDataDescCreate(&data, buf,
			static_cast<ULONG>((wcslen(buf) + 1) * sizeof(wchar_t)));

		EventWrite(g_hProvider, &desc, 1, &data);
	}
}