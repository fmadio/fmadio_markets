# Project Rules
Only read and modify files within this directory. Do not access files outside of this folder.

# Character Set

- All files (source code, headers, markdown, comments) must contain only standard ASCII characters. Never use unicode/UTF-8 characters such as em dashes, smart quotes, arrows, box-drawing characters, emoji, or math symbols.
- Use ASCII equivalents instead: `-` for dashes, `->` for arrows, `+--` for tree diagrams, `>=` / `<=` for comparisons.

# C Coding style

## Braces

- Always place opening and closing braces on their **own lines** (Allman style).
- Always use braces `{}` for every block, including single-line `if`, `else`, `for`, `while`, and `do` statements - never omit them.

```c
// CORRECT:
if (condition)
{
    doSomething();
}

// WRONG: - brace on same line
if (condition) {
    doSomething();
}

// WRONG: - no braces
if (condition)
    doSomething();
```

```c
// CORRECT: - else on its own lines
if (condition)
{
    doSomething();
}
else
{
    doSomethingElse();
}
```

## Indentation

- Use tabs for indentation (displayed as 4 spaces).
- Each nested block indents one additional level.
- Do not mix tabs and spaces.

```c
// CORRECT:
for (int i = 0; i < count; i++)
{
    if (items[i].active)
    {
        process(items[i]);
    }
}
```

## Line Length

- there is no maximum line length 

## Variable Declarations

- Declare variables as close as possible to their first use (C99).
- Do not declare all variables at the top of a function.

```c
// CORRECT:
for (int i = 0; i < count; i++)
{
    int value = items[i].value;
    process(value);
}

// WRONG: - declared far from use
int i;
int value;
// ... many lines later ...
for (i = 0; i < count; i++)
{
    value = items[i].value;
    process(value);
}
```

## Basic Types

Always use the project's fixed-width types from `include/fTypes.h` instead of standard C types. Never use `int`, `long`, `unsigned int`, etc. when the bit width matters.

| Type | Meaning |
|------|---------|
| `u8` | unsigned 8-bit |
| `s8` | signed 8-bit |
| `u16` | unsigned 16-bit |
| `s16` | signed 16-bit |
| `u32` | unsigned 32-bit |
| `s32` | signed 32-bit |
| `u64` | unsigned 64-bit |
| `s64` | signed 64-bit |
| `u128` | unsigned 128-bit |
| `bool` | boolean (`true` / `false`) |

```c
// CORRECT:
u32 packetLen;
s64 timestamp;
u8* buffer;

// WRONG:
unsigned int packetLen;
long long timestamp;
unsigned char* buffer;
```

Use the helper macros for size and time constants:

```c
kKB(4)          // 4 kilobytes as u64
kMB(16)         // 16 megabytes as u64
kGB(1)          // 1 gigabyte as u64
k1E9            // 1,000,000,000 (nanoseconds per second)
```

## Naming Conventions

- Use `camelCase` for variables and functions.
- Functions follow **noun-verb-suffix** order: the subject comes first, then the action, then an optional qualifier.

| Kind | Convention | Example |
|------|-----------|---------|
| Variables | `camelCase` | `itemCount` |
| Functions | `camelCase` noun-verb-suffix | `rowGroupParse()`, `bufferReadU32()` |
| Typedefs / structs | `PascalCase` with `_t` suffix | `RowGroup_t` |
| Macros / constants | `ALL_CAPS` | `MAX_COLUMNS` |
| Enum values | `ALL_CAPS` | `TYPE_INT32` |

- Structure and typedef names always end with the `_t` suffix.

```c
// CORRECT:
typedef struct
{
    u32 length;
} RowGroup_t;

// WRONG: - missing _t suffix
typedef struct
{
    u32 length;
} RowGroup;
```

## Pointer Declarations

- Place the `*` adjacent to the **type**, not the variable name.

```c
// CORRECT:
int* ptr;
char* name;

// WRONG:
int *ptr;
int * ptr;
```

## Switch Statements

- `case` labels are at the same indent level as `switch`.
- The body of each case indents one level from `case`.
- Always include a `default` branch.
- Use braces around a case body only when it declares a local variable.

```c
// CORRECT:
switch (type)
{
case TYPE_INT32:
    handle_int(val);
    break;
case TYPE_FLOAT:
    handle_float(val);
    break;
default:
    handle_unknown(val);
    break;
}
```

## Function Declarations

- Return type and function name go on the **same line**.
- Opening brace goes on its own line (Allman style, consistent with other blocks).

```c
// CORRECT:
int parse_row_group(RowGroup* rg, Buffer* buf)
{
    // ...
}

// WRONG: - return type on separate line
int
parse_row_group(RowGroup* rg, Buffer* buf)
{
    // ...
}
```

## Header Guards

- Use `#pragma once` at the top of every header file.

```c
// CORRECT:
#pragma once

// contents of header...
```

# Project: fmadio_markets

General purpose framework for decoding market data / order execution protocols
from PCAP files into parquet, assisted by Claude. Owner: aaron@fmad.com (fmad
engineering / fmadio).

## Layout

- src/main.c            - pcap reader (usec + nsec magic, file via -r or stdin),
                          VLAN strip (0x8100/0x9100/0x88a8 incl QinQ), IPv4
                          TCP/UDP identification, ProcessPacket/ProcessTCP/
                          ProcessUDP dispatch, stats + 10 sec status line,
                          parquet open/close, -o output option
- src/fTypes.h          - fixed width types (u8..u128 as unsigned long long
                          etc), kKB/kMB/kGB, k1E9, INLINE, clock_ns, rdtsc,
                          swap16/32/64/128, FormatTS, clock_date_t, ns2clock,
                          ns2str family
- src/fParquet.h        - Parquet_t context: duckdb db/con/appender + fileName
                          + tableName. Opened generic in main.c (parquetOpen /
                          parquetClose, COPY <table> TO '<file>' FORMAT PARQUET
                          on close), schema created by the protocol decoder
- protocol/nasdaq_md_itch5/
    nasdaq_md_itch5.md  - decoder reference: MoldUDP64 framing, all 23 ITCH 5.0
                          messages w/ offsets, appendices, sec 7 = flat parquet
                          schema (71 cols), sec 8 = multicast groups/ports/
                          subnets for Nasdaq/NTX/PSX
    nasdaq_md_itch5.c/h - Protocol_ITCH5SchemaCreate (table "itch" + appender),
                          Protocol_ITCH5PacketClassify (dst multicast group +
                          port match, 18 endpoints w/ market char + human name),
                          Protocol_ITCH5Decode (MoldUDP64 walk, all 23 message
                          types, one parquet row per message)
    *.pdf               - source specs (extract with pdftotext -layout)

## Build / run

- make                  -> src/fmadio_markets (gcc, -Wall -Wextra clean,
                          -I/usr/local/include -Isrc -Iprotocol/nasdaq_md_itch5,
                          links -lduckdb from /usr/local/lib)
- src/fmadio_markets -r <pcap> -o <out.parquet>
- summary on stderr: bytes/pkts/tcp/udp/other/ITCH5 pkts/ITCH5 msgs, duration,
  avg Gbps and peak Gbps (1 msec burst) from pcap timestamps
- status line every 10 sec; wall clock checked only every 64K packets
  (STATUS_CHECK_MASK) because clock_gettime per packet is too slow

## Protocol decoder conventions

- one directory per protocol under protocol/
- public functions prefixed Protocol_ e.g. Protocol_ITCH5Decode
- decoder owns its parquet schema (flat, union of all protocol columns, NULL
  for absent fields) and sets pq->tableName
- ProcessUDP/ProcessTCP receive Parquet_t* and dispatch by classifier
- all timestamps u64 nanoseconds; pcapTS = ns since epoch, ITCH timestampNS =
  ns since midnight ET; prices DECIMAL(16,4) / DECIMAL(20,8) via
  duckdb_append_double

## Validation status (2023-08-22 Nasdaq NY4 capture, session 000010058B/59B)

- vs mdgap.csv (3rd party, 399.7M rows): all 399,621,195 parquet msgs match
  seq + timestamp exactly; the 65,535 csv-only rows are a 3rd party bug
  (MoldUDP64 End of Session msgCount 0xFFFF miscounted as real messages)
- vs OMI tshark json (428,122 msgs, 17 fields): zero differences after fixing
  the json flattener (not the decoder)
- tshark -T ek caveats: duplicate json keys in mixed-type packets (python
  json.loads keeps last silently - use object_pairs_hook), fields grouped by
  message-type subtree destroying wire order, Y message uses 'locatecode' not
  'stocklocate'. Prefer -T json or -T fields -E occurrence=a
- OMI wireshark-lua dissectors: load single file via
  tshark -X lua_script:<file.lua>; loading the whole repo as plugins breaks
  (some dissectors have lua errors); PSX/Nasdaq ITCH heuristics both claim
  port 26477 - force with -d udp.port==26477,<name>

## Environment notes

- repo root dir is NOT writable for new files by the claude user (existing
  files are); create new files under src/ or protocol/
- installs (apt-get) and network access need the user to run them via the
  ! prefix; poppler-utils (pdftotext) installed; tshark availability depends
  on user install
- duckdb CLI + libduckdb (duckdb.h /usr/local/include, libduckdb.so
  /usr/local/lib) installed; this duckdb version lacks large_number_rendering;
  use format('{:,}', x) for thousand separators, GROUP BY ROLLUP for totals
- big reference files at repo root: mdgap.csv (~30GB),
  ny4-xnas-tvitch-20230822.pcap.tshark.json(.1m), fmadio_markets.parquet
  (399.6M rows) - use duckdb for any analysis, never load into memory
