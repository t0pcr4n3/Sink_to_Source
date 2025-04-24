vuln_pattern_sweeper.py
----------------------------------
🔍 What We’ll Detect in the Script
✅ Calls to dangerous functions

memcpy(...), memmove(...), strcpy(...)

✅ Presence of suspicious length parsing

ntohs(...), ntohl(...), or *(uint16_t *)...

✅ Static buffer declarations

char buffer[4096], uint8_t buf[...], etc.

✅ Missing bounds check between length parsing and memcpy
