# fmadio_markets

Market data protocol decoders on the fast path: PCAP in, Parquet out.

Written in C99 (gcc, -Wall -Wextra clean), with libduckdb for parquet output.
Each protocol decoder is generated and validated with the assistance of Claude
from the official exchange specifications (PDFs checked in alongside each
decoder).

## Protocols

| Protocol | Directory | Status |
|----------|-----------|--------|
| Nasdaq TotalView-ITCH 5.0 over MoldUDP64 | protocol/nasdaq_md_itch5 | synthetic 27/27 PASS, real capture validated vs 3rd party seq reference (399.6M msgs, 0 diffs) and OMI tshark dissector (428K msgs, 0 field diffs) |
| OPRA Pillar Binary v6 | protocol/opra_md_pillar6 | synthetic 29/29 PASS, real capture validation pending data |

Each protocol directory contains:

- `<protocol>.md` - decoder reference distilled from the official specs:
  transport framing, every message layout with byte offsets, the flat parquet
  schema, multicast addressing, and validation methodology/results
- `<protocol>.c/.h` - the decoder: packet classifier (multicast group + port),
  message decode, parquet schema
- `*.pdf` - the official source specifications
- `validate/` - repeatable luajit + duckdb validation suite (exits nonzero on
  failure, CI ready)

## Build

```
make            # -> src/fmadio_markets
```

Requires gcc, libduckdb (duckdb.h / libduckdb.so under /usr/local). The
validation suites additionally use luajit and the duckdb CLI.

## Run

```
src/fmadio_markets -r <capture.pcap> -o <out.parq> [-p <protocol>]

  -r <pcap file>     read from a pcap file (default: stdin, e.g. zstdcat pcap.zst |)
  -o <parquet file>  output parquet file (default: fmadio_markets.parq)
  -p <protocol>      nasdaq_md_itch5 | itch5 (default)
                     opra_md_pillar6 | opra
```

The decoder classifies UDP packets by multicast group + port, decodes every
protocol message into one row of a flat parquet table (union of all protocol
columns, NULL for absent fields), and prints a processing summary (packet/
message counts, duration, average and 1 msec burst peak bandwidth from the
pcap timestamps) on stderr.

## Validation

```
cd protocol/nasdaq_md_itch5/validate && make synthetic && make real && make json_1m
cd protocol/opra_md_pillar6/validate && make synthetic
```

See section 9 of each protocol's `.md` for methodology, input provenance
(md5sums, row counts) and findings, including documented bugs/quirks in the
third party reference tools.
