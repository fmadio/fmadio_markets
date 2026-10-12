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
from PCAP files into parquet, assisted by Claude. 

## Layout

- src/main.c            - pcap reader (usec + nsec magic, file via -r or stdin),
                          VLAN strip (0x8100/0x9100/0x88a8 incl QinQ), IPv4
                          TCP/UDP identification, ProcessPacket/ProcessTCP/
                          ProcessUDP dispatch, stats + 10 sec status line,
                          parquet open/close, -o output option, -p protocol
                          selection (Protocol_t enum, one active decoder per
                          run owning the single parquet table; default is
                          autodetect - first UDP packet matching a protocol
                          classifier locks in the decoder and creates its
                          schema, no match at EOF = no parquet written),
                          -t output rotation (off by default; libduckdb
                          buffers the whole table in memory, so with -t the
                          output is flushed and a new file started on every
                          -t period boundary in pcap time, files named
                          <stem>_<YYYYMMDD_HHMMSS UTC of window start><ext>,
                          empty windows still write a file, -t 0 = no
                          rotation, single file named exactly -o)
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
- protocol/opra_md_pillar6/
    opra_md_pillar6.md  - decoder reference: 21 byte transmission block header,
                          block/message sequence numbering rules, all 9 message
                          categories (a d f k q C H R Y) w/ offsets, BBO
                          indicator/appendage tables, denominator codes, sec 7 =
                          flat parquet schema (47 cols), sec 8 = fully patterned
                          multicast addressing (lines 1-96, 220-225, GTH
                          201-204, A/B streams, prod/retrans/playback), sec 9 =
                          validation status
    opra_md_pillar6.c/h - Protocol_OPRA6SchemaCreate (table "opra" + appender),
                          Protocol_OPRA6PacketClassify (computes line/stream/
                          feedType arithmetically from group+port into
                          OPRA6Endpoint_t; both must agree), Protocol_OPRA6Decode
                          (block walk, all 9 categories, denominator price
                          scaling, BBO appendages, one parquet row per message).
                          NOTE: no per-message length field in OPRA - message
                          length derives from category + BBO indicator; unknown
                          category aborts the rest of the block
    *.pdf               - source specs: OPRA_Pillar_Output_Specification.pdf
                          (v6.4a) + OPRA_Common_IP_Multicast_Distribution_
                          Network.pdf (v1.59), extract with pdftotext -layout
    validate/           - luajit validation suite, see Validation section
- data/                 - symlink to /mnt/data/markets_data (may appear broken
                          until mounted/populated); data/protocol/nasdaq_md_itch5/
                          holds the real capture + references, all zstd:
                          ny4-xnas-tvitch-20230822.pcap.zst (10GB, 34GB raw),
                          .pcap.mdgap.seqno.csv.zst (3rd party seq reference),
                          .pcap.tshark.json.{1m,20m}.zst + .tshark.10m.json.zst
                          (OMI tshark ek exports); no OPRA capture yet
                          (data/protocol/opra_md_pillar6/ pending)

## Build / run

- make                  -> src/fmadio_markets (gcc, -Wall -Wextra clean,
                          -I/usr/local/include -Isrc -Iprotocol/<each protocol>,
                          links -lduckdb from /usr/local/lib)
- src/fmadio_markets -r <pcap> -o <out.parq> [-p <protocol>] [-t <sec>]
- -p selects the decoder: auto (default, autodetects from multicast group +
  port classification), nasdaq_md_itch5 | itch5, or opra_md_pillar6 | opra
- -t sets the output rotation period in seconds of pcap time (default: no
  rotation, single file); each rotated file is <stem>_<YYYYMMDD_HHMMSS><ext>
  with the UTC start of its period-aligned window; validation suites pass
  -t 0 explicitly to pin the single-file behavior
- summary on stderr: bytes/pkts/tcp/udp/other + per-protocol pkts/msgs
  (Pkt ITCH5/Msg ITCH5 or Pkt OPRA6/Msg OPRA6), files written, duration,
  avg Gbps and peak Gbps (1 msec burst) from pcap timestamps
- status line every 10 sec; wall clock checked only every 64K packets
  (STATUS_CHECK_MASK) because clock_gettime per packet is too slow

## Protocol decoder conventions

- one directory per protocol under protocol/; new protocol = decoder .c/.h +
  <protocol>.md reference doc + validate/ suite, wired into the Makefile,
  main.c Protocol_t enum / -p parsing / ProcessUDP dispatch /
  protocolSchemaCreate switch / protocolAutoDetect classifier chain /
  summary lines
- public functions prefixed Protocol_ e.g. Protocol_ITCH5Decode,
  Protocol_OPRA6Decode
- decoder owns its parquet schema (flat, union of all protocol columns, NULL
  for absent fields) and sets pq->tableName; one protocol active per run
- ProcessUDP/ProcessTCP receive Parquet_t* and dispatch by classifier; when
  the transport layer needs endpoint context (e.g. OPRA line/stream/feedType)
  the classifier fills an <Protocol>Endpoint_t that is passed to the decoder
- all timestamps u64 nanoseconds; pcapTS = ns since epoch, ITCH timestampNS =
  ns since midnight ET, OPRA blockTimestampNS = ns since epoch (only per-block,
  no per-message timestamp); prices DECIMAL(16,4) / DECIMAL(20,8) via
  duckdb_append_double (OPRA scales by wire denominator codes at decode time)

## Validation suites (protocol/<protocol>/validate/, luajit + duckdb CLI)

Repeatable, all targets exit nonzero on failure (CI ready). Scripts named
validate_*.lua, gen_pcap.lua builds the synthetic input. Full methodology +
input file md5sums/counts in each protocol's .md section 9.

### nasdaq_md_itch5/validate/

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

### opra_md_pillar6/validate/

- make synthetic  - gen_pcap.lua builds a 17 packet pcap: all 9 categories,
                    every BBO appendage variant (none/bid/offer/double on long
                    and short quotes), denominator codes A B C D E H I + short
                    quote implied A/B, signed negative netChange, 8 byte denom
                    H underlying, pad bytes, block checksums, implicit seq
                    numbering, zero quote, prod/retrans/playback + GTH + A/B
                    stream classification, 4 negative packets (wrong port, CQS
                    lookalike group, wrong version, wrong feed indicator) and
                    an unknown-category-mid-block case;
                    validate_synthetic.lua decodes (-p opra) and field-checks
                    29 assertions. Status: 29/29 PASS
- make real       - PENDING: no OPRA capture / 3rd party reference yet under
                    data/protocol/opra_md_pillar6/. Join key must be
                    (line, msgSeqNo) - OPRA has no per-message timestamp.
                    Methodology in opra_md_pillar6.md section 9.2

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
- OPRA gotchas (vs MoldUDP64): no per-message length field (length = category
  + BBO indicator; unknown category = rest of block undecodable), no
  per-message timestamp (block timestamp only), block seq number is really a
  per-line message seq number with exceptions (H/N line integrity = last
  transmitted seq + does not consume; H/C start of day = 0; retrans blocks =
  first msg seq), 224.0.200.x subnet is SHARED with CTS/CQS so the classifier
  must match exact group octet + port pairs, categories C and H always one
  per block, odd blocks get one 0x00 pad byte

## Environment notes

- repo root dir is NOT writable for new files by the claude user (existing
  files are); create new files under src/ or protocol/. New protocol dirs
  dropped in by the repo owner may arrive mode 755 owner fmadio - ask the user
  to chmod (via ! prefix) before writing into them
- installs (apt-get) and network access need the user to run them via the
  ! prefix; poppler-utils (pdftotext) installed; tshark availability depends
  on user install
- duckdb CLI + libduckdb (duckdb.h /usr/local/include, libduckdb.so
  /usr/local/lib) installed; this duckdb version lacks large_number_rendering;
  use format('{:,}', x) for thousand separators, GROUP BY ROLLUP for totals
- test code writes parquet files with a .parq extension; duckdb's replacement
  scan does NOT auto-detect .parq (FROM 'x.parq' fails with Catalog Error) -
  always use read_parquet('x.parq') in queries
- luajit 2.1 (/usr/bin/luajit) + zstd/zstdcat installed. LuaJIT numbers are
  doubles: keep epoch-ns timestamps (>2^53) as STRINGS in lua, let duckdb
  parse them
- canonical big data lives under data/protocol/<protocol>/ as .zst; legacy
  uncompressed copies may exist at repo root (mdgap.csv, fmadio_markets.parquet,
  *.tshark.json*) - use duckdb for any analysis, never load into memory;
  machine has 192 cores / 715GB ram, 400Mx400M duckdb joins take ~2-3 min
