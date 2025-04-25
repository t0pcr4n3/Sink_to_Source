vuln_pattern_sweeper.py
----------------------------------
## 🧠 What It Looks For

| Pattern              | What It Means                                               |
|----------------------|-------------------------------------------------------------|
| `static_buffer`      | Fixed-size buffer (possible overflow target)                |
| `memcpy_call`        | Copying memory — usually where overflows happen             |
| `ntohs_parse`        | Reading untrusted length field from network                 |
| `raw_uint16_cast`    | Cast from raw data into length-type field                   |
| `option_length_usage`| Using an untrusted field                                    |
| `no_bounds_check`    | `memcpy` directly using `ntohs(...)` size — yikes 😱         |

🔍 What We’ll Detect in the Script

✅ Calls to dangerous functions : memcpy(...), memmove(...), strcpy(...)

✅ Presence of suspicious length parsing : ntohs(...), ntohl(...), or *(uint16_t *)...

✅ Static buffer declarations : char buffer[4096], uint8_t buf[...], etc.

✅ Missing bounds check between length parsing and memcpy
