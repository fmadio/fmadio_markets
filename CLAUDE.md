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
    validate/           - luajit validation suite, see Validation section
- data/                 - symlink to /mnt/data/markets_data (may appear broken
                          until mounted/populated); data/protocol/nasdaq_md_itch5/
                          holds the real capture + references, all zstd:
                          ny4-xnas-tvitch-20230822.pcap.zst (10GB, 34GB raw),
                          .pcap.mdgap.seqno.csv.zst (3rd party seq reference),
                          .pcap.tshark.json.{1m,20m}.zst + .tshark.10m.json.zst
                          (OMI tshark ek exports)

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

## Validation suite (protocol/nasdaq_md_itch5/validate/, luajit + duckdb CLI)

Repeatable, all targets exit nonzero on failure (CI ready). Scripts named
validate_*.lua. Full methodology + input file md5sums/counts in
nasdaq_md_itch5.md section 9.

- make synthetic  - gen_pcap.lua builds a pcap with all 23 message types +
                    known values (multi-message mold packets, heartbeat);
                    validate_synthetic.lua decodes and field-checks 27
                    assertions. Status: 27/27 PASS
- make real       - validate_real.lua runs the whole pipeline: zstdcat pcap.zst
                    | decoder -o <temp parquet in validate/> then duckdb join
                    vs mdgap seqno csv (seq + pcap timestamp). Knows the End of
                    Session artifact signature (3rd party counts the 0xFFFF
                    sentinel as 65535 msgs from one packet/one timestamp) and
                    passes it as explained. Status: 3/3 PASS, 399,621,195 msgs,
                    decode takes ~11 min
- make json_1m    - validate_real_json_1m.lua flattens the OMI tshark ek json
                    slice (pattern-walks raw text in key order, no json lib)
                    and compares 17 fields/msg vs the parquet on (session,
                    seq). Reuses parquet from make real if present. Status:
                    18/18 PASS, 428,122 msgs, zero field diffs
- override inputs: make real REAL_PCAP=... REAL_CSV=...; duckdb reads .csv.zst
  natively, pcap.zst is streamed via zstdcat into decoder stdin

## Validation findings / external tool caveats

- 2023-08-22 Nasdaq NY4 capture, mold sessions 000010058B (prev session tail,
  247,829 msgs, seq 406,312,900+) and 000010059B (399,373,366 msgs, seq 1+)
- 3rd party mdgap tool bug: MoldUDP64 End of Session (msgCount 0xFFFF) counted
  as 65,535 real messages; decoder is correct to emit none
- tshark -T ek caveats (all handled in validate_real_json_1m.lua): duplicate
  json keys in mixed-type packets (json.loads keeps last silently), fields
  grouped by message-type subtree destroying wire order for same-named fields,
  Y message uses 'locatecode' not 'stocklocate'. Prefer -T json or
  -T fields -E occurrence=a
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
- luajit 2.1 (/usr/bin/luajit) + zstd/zstdcat installed. LuaJIT numbers are
  doubles: keep epoch-ns timestamps (>2^53) as STRINGS in lua, let duckdb
  parse them
- canonical big data lives under data/protocol/<protocol>/ as .zst; legacy
  uncompressed copies may exist at repo root (mdgap.csv, fmadio_markets.parquet,
  *.tshark.json*) - use duckdb for any analysis, never load into memory;
  machine has 192 cores / 715GB ram, 400Mx400M duckdb joins take ~2-3 min
