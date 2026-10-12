# EFI Latency Test Packet - Decoder Reference

REVERSE ENGINEERED - no vendor specification. Everything in this document is
derived from the single reference capture:

- `data/protocol/efilatency/efilatency_seq_indicator.pcap` - 40 packets,
  nanosecond pcap (magic 0xa1b23c4d), captured 2026-10-09 11:07:23 UTC,
  42.1 usec span

Inferences that go beyond what the capture directly shows are marked
(INFERRED). Field widths/offsets are exact observations.

efilatency is a UDP latency test / sequence indicator protocol: a generator
emits fixed size 64 byte UDP payloads carrying an incrementing sequence
number and a one byte phase indicator. Each sequence number is transmitted
on TWO paths (two source MACs, two capture ports) so the pair's capture
timestamps measure the latency difference between the paths.

## Protocol Stack

```
Ethernet / IPv4 / UDP
  +-- efilatency message                 (fixed 64 byte UDP payload)
```

- One UDP datagram = one message. No framing layer, no message type byte,
  no session layer.
- All integer fields are BIG endian (network order).
- Fixed size: UDP length is always 72 (8 byte UDP header + 64 byte payload).

---

## 1. Message Layout (64 bytes, the entire UDP payload)

| Field     | Offset | Length | Type    | Notes                                            |
|-----------|--------|--------|---------|--------------------------------------------------|
| seqNo     | 0      | 8      | u64 BE  | Sequence number; starts at 1, increments by 1    |
| indicator | 8      | 1      | ASCII   | Phase indicator character; observed 'W' and 'N'  |
| padding   | 9      | 55     | -       | All zero in every captured packet                |

### 1.1 seqNo

- Starts at 1 and increments by 1 per generated message (observed 1..20,
  no gaps, no wrap).
- The SAME seqNo is carried by both transmission arms: the capture holds
  exactly 2 packets per seqNo, one from each source MAC. The sequence is
  global to the generator, not per arm.
- Big endian confirmed by value range (BE reads 1..20; LE would read
  2^56-scale values).

### 1.2 indicator

Observed values, exactly 10 sequence numbers each:

| Value | Hex  | Observed on | Meaning                                  |
|-------|------|-------------|------------------------------------------|
| 'W'   | 0x57 | seqNo 1-10  | (INFERRED) Warmup phase                  |
| 'N'   | 0x4e | seqNo 11-20 | (INFERRED) Normal / measured phase       |

- The indicator flips once, W -> N, at seqNo 11; both arms always agree.
- Treat as an opaque 1 byte ASCII character in the decoder; store it as a
  string column and do NOT restrict to the observed set (other phase
  characters may exist in other runs).
- Byte 9 is zero in every packet, so a 2 byte field reading 0x5700/0x4e00
  cannot be ruled out, but 1 byte ASCII + zero padding is the natural read
  (values are printable characters and the filename says "seq_indicator").

---

## 2. Capture Environment (reference capture specifics)

These describe the reference capture, NOT necessarily the protocol:

- Ethernet dst ff:ff:ff:ff:ff:ff (broadcast); src alternates between
  74:27:2c:83:23:e0 (arm A) and 74:27:2c:83:74:60 (arm B).
- IPv4 172.16.133.100 -> 172.1.2.3 (unicast IPs, broadcast MAC), TTL 64,
  IP ID 0, no fragmentation. Identical on both arms.
- UDP 8080 -> 8080, checksum present and valid (varies with seqNo).
- Packets per arm are ~1.7 usec apart; the paired arm B packet follows the
  arm A packet by roughly 0.9 - 4.6 usec.
- Every frame carries an Arista 7130 (metamako) timestamp trailer in the
  slack past the IP datagram, already handled generically by main.c
  footerRead and surfaced as the frame_pb* columns. Slack layout here is
  20 bytes: 4 bytes (probably the sender's original FCS, random-looking
  per packet) + 12 byte trailer (sec/ns/flags/deviceID/portID, big endian)
  + 4 byte recomputed FCS, i.e. the trailer sits at frame end -16, the
  "-4 with FCS" position footerRead probes.
- Trailer deviceID 56365 (0xdc2d) on all packets; portID 20 = arm A
  (MAC ...23:e0), portID 19 = arm B (MAC ...74:60). Trailer sec/ns equals
  the pcap timestamp exactly (the trailer clock IS the capture clock).

---

## 3. Decoder Implementation Notes

- One parquet row per UDP datagram (there is exactly one message per
  datagram).
- Decode requires only: payload length >= 9; read u64 BE seqNo at offset 0,
  1 ASCII char at offset 8. Emit the row even if the padding is non-zero or
  the payload is not exactly 64 bytes (future runs may use the padding);
  payloads shorter than 9 bytes decode to no row.
- No decimal scaling, no per flow state, no endpoint context beyond the
  flow 5-tuple: the <Protocol>Endpoint_t is unused (classify fills
  nothing).
- Latency analysis (pairing arm A/B rows by msg_seqNo and differencing
  frame_ts / frame_pbTS) is a downstream query concern, not the decoder's:

```sql
SELECT a.msg_seqNo, a.msg_indicator,
       b.frame_ts - a.frame_ts AS delta_ns
FROM   read_parquet('out.parquet') a
JOIN   read_parquet('out.parquet') b
       ON a.msg_seqNo = b.msg_seqNo AND a.frame_pbPortID > b.frame_pbPortID
ORDER  BY a.msg_seqNo;
```

---

## 7. Flat Parquet Schema (table "efilatency")

15 shared capture layer columns (CAPTURE_SCHEMA_COLUMNS, appended via
packetInfoAppend) + 3 ethernet header columns + 2 message columns = 20
columns total. The ethernet columns are efilatency specific (NOT part of
the shared capture schema): the transmission arms differ only in source
MAC and capture trailer port, so the MAC identifies the arm directly.

| # | Column          | Type   | Notes                                      |
|---|-----------------|--------|---------------------------------------------|
| 1-15 | frame_*      | -      | shared capture layer (src/fCapture.h)       |
| 16 | frame_macSrc   | STRING | source MAC, colon hex (arm A / arm B)       |
| 17 | frame_macDst   | STRING | destination MAC, colon hex                  |
| 18 | frame_etherType| UINT16 | outermost wire ethertype (0x0800 = 2048 untagged IPv4) |
| 19 | msg_seqNo      | UINT64 | sequence number (payload offset 0)          |
| 20 | msg_indicator  | STRING | 1 character phase indicator (offset 8)      |

No hdr_* group: the protocol has no transport header and the classifier
carries no endpoint context.

---

## 8. Addressing / Classification

There is no multicast group plan or reserved port: the reference capture
uses UDP unicast 8080 -> 8080 with a broadcast destination MAC. The
framework classifies flows on the 4-tuple only (fProtocol.h classify sees
no payload), so the classifier matches source AND destination port == 8080
- requiring BOTH sides narrows plain HTTP-alt traffic, which is client
ephemeral port -> 8080. The fixed payload shape (length >= 9, u64 BE seqNo
+ ASCII indicator) is enforced per datagram in decode instead; short
payloads decode to no row.

The seqNo value is NOT part of any check (mid-run captures start at
arbitrary values).

Autodetect: registered normally (no .noAutoDetect). The 8080 -> 8080 match
is weaker than the market data protocols' multicast group + port matches,
but autodetect only locks the first MATCHING protocol per run, and no
registered feed overlaps port 8080 on both sides; efilatency sorts between
eurex_* and euronext_* in link order. For mixed captures, pin the decoder
with -p efilatency / -p efilat.

---

## 9. Decoder Validation

### 9.1 Reference capture - PASS (manual duckdb checks, 2026-10-12)

Decoder run against the reference capture (both -p auto and -p efilat lock
in efilatency), all checks pass:

- 40 rows, msg_seqNo 1..20 each appearing exactly twice
- msg_indicator = 'W' for seqNo 1-10, 'N' for seqNo 11-20
- frame_pbDeviceID = 56365 on all rows; frame_pbPortID in {19, 20} with
  20 rows each; frame_pbTS == frame_ts on every row
- 1 flow, 40 packets, 40 messages in the run summary
- arm pair deltas (section 3 query) ~0.9 - 4.6 usec, matching the raw pcap

### 9.2 Synthetic unit test - PENDING

No validate/ suite yet; when added it should replay the reference capture
checks above plus synthetic edge cases (payload < 9 bytes = no row,
non-64-byte payload still decodes, 0x00 indicator = NULL).
