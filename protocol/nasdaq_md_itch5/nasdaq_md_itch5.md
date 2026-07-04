# Nasdaq TotalView-ITCH 5.0 over MoldUDP64 - Decoder Reference

Summary of `nasdaq_md_itch5/NQTVITCHspecification.pdf` (TotalView-ITCH 5.0) and
`nasdaq_md_itch5/moldudp64.pdf` (MoldUDP64 V1.00), containing everything required to
decode the feed from raw UDP packets.

## Protocol Stack

```
Ethernet / (VLAN) / IPv4 / UDP
  +-- MoldUDP64 Downstream Packet        (20 byte header + N message blocks)
        +-- Message Block                 (2 byte length + message data)
              +-- ITCH 5.0 message        (first byte = message type)
```

- ITCH may also be delivered via SoupBinTCP; over UDP multicast it is always MoldUDP64.
- **All integer fields in both MoldUDP64 and ITCH are big endian (network byte order), unsigned unless noted.**

---

## 1. MoldUDP64 Transport Layer

One UDP datagram = one MoldUDP64 Downstream Packet.

### 1.1 Downstream Packet Header (20 bytes)

| Field           | Offset | Length | Type  | Notes                                             |
|-----------------|--------|--------|-------|---------------------------------------------------|
| Session         | 0      | 10     | ANUM  | Alphanumeric session identifier                   |
| Sequence Number | 10     | 8      | NUM   | Sequence number of the FIRST message in packet    |
| Message Count   | 18     | 2      | NUM   | Number of message blocks in this packet           |

- Messages after the first are implicitly numbered sequentially (seq, seq+1, seq+2, ...).
- **Message Count == 0x0000**: heartbeat (sent ~1/sec, Sequence Number = next expected). No message blocks follow.
- **Message Count == 0xFFFF**: end of session (also carries next expected Sequence Number). No message blocks follow.

### 1.2 Message Block (repeated Message Count times)

| Field          | Offset | Length | Type | Notes                                              |
|----------------|--------|--------|------|----------------------------------------------------|
| Message Length | *      | 2      | NUM  | Byte count of Message Data only (excludes these 2 bytes) |
| Message Data   | *      | var    | -    | One complete ITCH message                          |

- First block starts at packet offset 20; each subsequent block starts immediately after the previous one.
- Total block size = Message Length + 2. Message Length may be 0.

### 1.3 Request Packet (client -> re-request server, unicast; same 20-byte layout)

| Field                   | Offset | Length | Notes                                  |
|-------------------------|--------|--------|----------------------------------------|
| Session                 | 0      | 10     | Session being requested                |
| Sequence Number         | 10     | 8      | First requested sequence number        |
| Requested Message Count | 18     | 2      | Number of messages to retransmit       |

Response is a standard Downstream Packet unicast back to the requester. Only needed
for live gap-fill; not needed for PCAP decode.

---

## 2. ITCH 5.0 Data Types

- **Integer**: big endian binary, unsigned.
- **Alpha**: ASCII, left justified, right padded with spaces.
- **Price (4)**: 4-byte unsigned integer with 4 implied decimal places (divide by 10,000). Max 200,000.0000.
- **Price (8)**: 8-byte unsigned integer with 8 implied decimal places (divide by 100,000,000). Used only in MWCB Decline Level.
- **Timestamp**: **6 bytes**, nanoseconds since midnight (Eastern). Read as a 48-bit big-endian integer.
- **Stock Locate**: dynamically assigned per day starting at 1; array index for symbol lookup, communicated via Stock Directory ("R"). 0 for non-stock-specific messages. Same position in every message.

### 2.1 Common message header (every ITCH message, first 11 bytes)

| Field           | Offset | Length | Type    |
|-----------------|--------|--------|---------|
| Message Type    | 0      | 1      | Alpha   |
| Stock Locate    | 1      | 2      | Integer |
| Tracking Number | 3      | 2      | Integer |
| Timestamp       | 5      | 6      | Integer (48-bit ns since midnight) |

### 2.2 Message type -> total length (bytes, including the type byte)

| Type | Message                          | Length |
|------|----------------------------------|--------|
| S    | System Event                     | 12 |
| R    | Stock Directory                  | 39 |
| H    | Stock Trading Action             | 25 |
| Y    | Reg SHO Restriction              | 20 |
| L    | Market Participant Position      | 26 |
| V    | MWCB Decline Level               | 35 |
| W    | MWCB Status                      | 12 |
| K    | IPO Quoting Period Update        | 28 |
| J    | LULD Auction Collar              | 35 |
| h    | Operational Halt                 | 21 |
| A    | Add Order (no MPID)              | 36 |
| F    | Add Order (MPID attribution)     | 40 |
| E    | Order Executed                   | 31 |
| C    | Order Executed With Price        | 36 |
| X    | Order Cancel                     | 23 |
| D    | Order Delete                     | 19 |
| U    | Order Replace                    | 35 |
| P    | Trade (non-cross)                | 44 |
| Q    | Cross Trade                      | 40 |
| B    | Broken Trade                     | 19 |
| I    | NOII                             | 50 |
| N    | Retail Price Improvement (RPII)  | 20 |
| O    | Direct Listing w/ Capital Raise  | 48 |

(The MoldUDP64 Message Length field is authoritative; the table is a cross-check.)

---

## 3. System / Administrative Messages

### 3.1 "S" - System Event (12 bytes)

| Field      | Offset | Length | Type  | Notes                |
|------------|--------|--------|-------|----------------------|
| Event Code | 11     | 1      | Alpha | See below            |

Event codes: `O` Start of Messages, `S` Start of System hours, `Q` Start of Market hours,
`M` End of Market hours, `E` End of System hours, `C` End of Messages.

### 3.2 "R" - Stock Directory (39 bytes)

Sent at start of day for all active symbols. Maps Stock Locate -> symbol.

| Field                     | Offset | Length | Type      |
|---------------------------|--------|--------|-----------|
| Stock                     | 11     | 8      | Alpha     |
| Market Category           | 19     | 1      | Alpha     |
| Financial Status Indicator| 20     | 1      | Alpha     |
| Round Lot Size            | 21     | 4      | Integer   |
| Round Lots Only           | 25     | 1      | Alpha (Y/N) |
| Issue Classification      | 26     | 1      | Alpha (Appendix D) |
| Issue Sub-Type            | 27     | 2      | Alpha (Appendix E) |
| Authenticity              | 29     | 1      | Alpha (P=live, T=test) |
| Short Sale Threshold Ind. | 30     | 1      | Alpha (Y/N/space) |
| IPO Flag                  | 31     | 1      | Alpha (Y/N/space) |
| LULD Reference Price Tier | 32     | 1      | Alpha (1/2/space) |
| ETP Flag                  | 33     | 1      | Alpha (Y/N/space) |
| ETP Leverage Factor       | 34     | 4      | Integer   |
| Inverse Indicator         | 38     | 1      | Alpha (Y/N) |

Market Category: `Q` Nasdaq Global Select, `G` Nasdaq Global, `S` Nasdaq Capital Market,
`N` NYSE, `A` NYSE American, `P` NYSE Arca, `Z` BATS, `V` IEX, space = N/A.

Financial Status (Nasdaq-listed): `D` Deficient, `E` Delinquent, `Q` Bankrupt, `S` Suspended,
`G` Deficient+Bankrupt, `H` Deficient+Delinquent, `J` Delinquent+Bankrupt,
`K` Deficient+Delinquent+Bankrupt, `C` ETP Creations/Redemptions Suspended, `N` Normal,
space = N/A (non-Nasdaq listed).

### 3.3 "H" - Stock Trading Action (25 bytes)

| Field         | Offset | Length | Type  |
|---------------|--------|--------|-------|
| Stock         | 11     | 8      | Alpha |
| Trading State | 19     | 1      | Alpha |
| Reserved      | 20     | 1      | Alpha |
| Reason        | 21     | 4      | Alpha (Appendix C) |

Trading State: `H` Halted (all markets), `P` Paused (Nasdaq-listed only),
`Q` Quotation-only period, `T` Trading on Nasdaq.

### 3.4 "Y" - Reg SHO Short Sale Price Test Restricted Indicator (20 bytes)

| Field          | Offset | Length | Type  |
|----------------|--------|--------|-------|
| Stock          | 11     | 8      | Alpha |
| Reg SHO Action | 19     | 1      | Alpha: `0` no test, `1` restriction (intraday drop), `2` restriction remains |

### 3.5 "L" - Market Participant Position (26 bytes)

| Field                    | Offset | Length | Type  |
|--------------------------|--------|--------|-------|
| MPID                     | 11     | 4      | Alpha |
| Stock                    | 15     | 8      | Alpha |
| Primary Market Maker     | 23     | 1      | Alpha (Y/N) |
| Market Maker Mode        | 24     | 1      | Alpha: `N` normal, `P` passive, `S` syndicate, `R` pre-syndicate, `L` penalty |
| Market Participant State | 25     | 1      | Alpha: `A` Active, `E` Excused/Withdrawn, `W` Withdrawn, `S` Suspended, `D` Deleted |

### 3.6 "V" - MWCB Decline Level (35 bytes) - Stock Locate always 0

| Field   | Offset | Length | Type      |
|---------|--------|--------|-----------|
| Level 1 | 11     | 8      | Price (8) |
| Level 2 | 19     | 8      | Price (8) |
| Level 3 | 27     | 8      | Price (8) |

### 3.7 "W" - MWCB Status (12 bytes) - Stock Locate always 0

| Field          | Offset | Length | Type  |
|----------------|--------|--------|-------|
| Breached Level | 11     | 1      | Alpha: `1` / `2` / `3` |

### 3.8 "K" - IPO Quoting Period Update (28 bytes) - Stock Locate always 0

| Field                         | Offset | Length | Type      |
|-------------------------------|--------|--------|-----------|
| Stock                         | 11     | 8      | Alpha     |
| IPO Quotation Release Time    | 19     | 4      | Integer, seconds since midnight (0 = canceled/postponed) |
| IPO Quotation Release Qualifier | 23   | 1      | Alpha: `A` anticipated, `C` canceled/postponed |
| IPO Price                     | 24     | 4      | Price (4) |

### 3.9 "J" - LULD Auction Collar (35 bytes)

| Field                          | Offset | Length | Type      |
|--------------------------------|--------|--------|-----------|
| Stock                          | 11     | 8      | Alpha     |
| Auction Collar Reference Price | 19     | 4      | Price (4) |
| Upper Auction Collar Price     | 23     | 4      | Price (4) |
| Lower Auction Collar Price     | 27     | 4      | Price (4) |
| Auction Collar Extension       | 31     | 4      | Integer   |

### 3.10 "h" - Operational Halt (21 bytes) - note lowercase type byte

| Field                  | Offset | Length | Type  |
|------------------------|--------|--------|-------|
| Stock                  | 11     | 8      | Alpha |
| Market Code            | 19     | 1      | Alpha: `Q` Nasdaq, `B` BX, `X` PSX |
| Operational Halt Action| 20     | 1      | Alpha: `H` halted, `T` trading resumed |

---

## 4. Order Book Messages

### 4.1 "A" - Add Order, No MPID Attribution (36 bytes)

| Field                  | Offset | Length | Type      |
|------------------------|--------|--------|-----------|
| Order Reference Number | 11     | 8      | Integer (day-unique) |
| Buy/Sell Indicator     | 19     | 1      | Alpha: `B` / `S` |
| Shares                 | 20     | 4      | Integer   |
| Stock                  | 24     | 8      | Alpha     |
| Price                  | 32     | 4      | Price (4) |

### 4.2 "F" - Add Order, MPID Attribution (40 bytes)

Same as "A" through offset 35, plus:

| Field       | Offset | Length | Type  |
|-------------|--------|--------|-------|
| Attribution | 36     | 4      | Alpha (MPID) |

### 4.3 "E" - Order Executed (31 bytes)

| Field                  | Offset | Length | Type    |
|------------------------|--------|--------|---------|
| Order Reference Number | 11     | 8      | Integer |
| Executed Shares        | 19     | 4      | Integer |
| Match Number           | 23     | 8      | Integer (day-unique; referenced by Broken Trade) |

Multiple executions for the same order ref are cumulative. Executes at the display price.

### 4.4 "C" - Order Executed With Price (36 bytes)

| Field                  | Offset | Length | Type      |
|------------------------|--------|--------|-----------|
| Order Reference Number | 11     | 8      | Integer   |
| Executed Shares        | 19     | 4      | Integer   |
| Match Number           | 23     | 8      | Integer   |
| Printable              | 31     | 1      | Alpha: `Y` / `N` (ignore `N` for time-and-sales / volume to avoid double counting) |
| Execution Price        | 32     | 4      | Price (4) |

### 4.5 "X" - Order Cancel (23 bytes) - partial cancel

| Field                  | Offset | Length | Type    |
|------------------------|--------|--------|---------|
| Order Reference Number | 11     | 8      | Integer |
| Cancelled Shares       | 19     | 4      | Integer |

### 4.6 "D" - Order Delete (19 bytes) - full cancel, remove order

| Field                  | Offset | Length | Type    |
|------------------------|--------|--------|---------|
| Order Reference Number | 11     | 8      | Integer |

### 4.7 "U" - Order Replace (35 bytes)

| Field                           | Offset | Length | Type      |
|---------------------------------|--------|--------|-----------|
| Original Order Reference Number | 11     | 8      | Integer   |
| New Order Reference Number      | 19     | 8      | Integer   |
| Shares                          | 27     | 4      | Integer (new total displayed qty) |
| Price                           | 31     | 4      | Price (4) (new display price) |

Side, stock, and MPID are NOT included - carry them over from the original Add Order.

**Book maintenance rule**: display shares = Add Order shares minus cumulative Executed /
Executed-With-Price / Cancelled shares for that order reference number; remove the order
when it reaches zero, on Order Delete, or (for the old ref) on Order Replace.

---

## 5. Trade Messages

### 5.1 "P" - Trade, Non-Cross (44 bytes) - hidden/non-displayed liquidity

| Field                  | Offset | Length | Type      | Notes |
|------------------------|--------|--------|-----------|-------|
| Order Reference Number | 11     | 8      | Integer   | Always 0 since 2010-12-06 |
| Buy/Sell Indicator     | 19     | 1      | Alpha     | Always `B` since 2014-07-14 |
| Shares                 | 20     | 4      | Integer   | |
| Stock                  | 24     | 8      | Alpha     | |
| Price                  | 32     | 4      | Price (4) | |
| Match Number           | 36     | 8      | Integer   | |

Does not affect the book; include in time-and-sales/volume.

### 5.2 "Q" - Cross Trade (40 bytes)

| Field        | Offset | Length | Type      |
|--------------|--------|--------|-----------|
| Shares       | 11     | 8      | Integer (note: 8 bytes) |
| Stock        | 19     | 8      | Alpha     |
| Cross Price  | 27     | 4      | Price (4) |
| Match Number | 31     | 8      | Integer   |
| Cross Type   | 39     | 1      | Alpha: `O` Opening, `C` Closing, `H` IPO/halted-paused cross |

### 5.3 "B" - Broken Trade (19 bytes)

| Field        | Offset | Length | Type    |
|--------------|--------|--------|---------|
| Match Number | 11     | 8      | Integer (execution being broken) |

Trade breaks are final. Book builders may ignore; time-and-sales must process.

---

## 6. Auction / Indicator Messages

### 6.1 "I" - Net Order Imbalance Indicator, NOII (50 bytes)

| Field                   | Offset | Length | Type      |
|-------------------------|--------|--------|-----------|
| Paired Shares           | 11     | 8      | Integer   |
| Imbalance Shares        | 19     | 8      | Integer   |
| Imbalance Direction     | 27     | 1      | Alpha: `B` buy, `S` sell, `N` none, `O` insufficient orders, `P` paused |
| Stock                   | 28     | 8      | Alpha     |
| Far Price               | 36     | 4      | Price (4) |
| Near Price              | 40     | 4      | Price (4) |
| Current Reference Price | 44     | 4      | Price (4) |
| Cross Type              | 48     | 1      | Alpha: `O` Opening, `C` Closing, `H` IPO/halted, `A` Extended Trading Close |
| Price Variation Indicator | 49   | 1      | Alpha: `L` <1%, `1`-`9` = 1-9.99% bands, `A` 10-19.99%, `B` 20-29.99%, `C` >=30%, space = N/A |

### 6.2 "N" - Retail Price Improvement Indicator, RPII (20 bytes)

| Field         | Offset | Length | Type  |
|---------------|--------|--------|-------|
| Stock         | 11     | 8      | Alpha |
| Interest Flag | 19     | 1      | Alpha: `B` buy side, `S` sell side, `A` both, `N` none |

### 6.3 "O" - Direct Listing with Capital Raise (48 bytes)

| Field                    | Offset | Length | Type      |
|--------------------------|--------|--------|-----------|
| Stock                    | 11     | 8      | Alpha     |
| Open Eligibility Status  | 19     | 1      | Alpha: `Y` / `N` |
| Minimum Allowable Price  | 20     | 4      | Price (4) |
| Maximum Allowable Price  | 24     | 4      | Price (4) |
| Near Execution Price     | 28     | 4      | Price (4) |
| Near Execution Time      | 32     | 8      | Integer   |
| Lower Price Range Collar | 40     | 4      | Price (4) |
| Upper Price Range Collar | 44     | 4      | Price (4) |

---

## Appendix C - Trading Action Reason Codes (4-byte Alpha, space padded)

Halts/pauses: `T1` News Pending, `T2` News Disseminated, `T5` Single Security Pause,
`T6` Regulatory Halt (Extraordinary Market Activity), `T8` Halt ETF, `T12` Info Requested
by Listing Market, `H4` Non-Compliance, `H9` Filings Not Current, `H10` SEC Suspension,
`H11` Regulatory Concern, `O1` Operations Halt, `LUDP` Volatility Pause,
`LUDS` Volatility Pause (Straddle), `MWC1`/`MWC2`/`MWC3` MWCB Halt Level 1/2/3,
`MWC0` MWCB carry-over, `IPO1` IPO Not Yet Trading, `M1` Corporate Action,
`M2` Quotation Not Available.

Resumptions: `T3` News and Resumption Times, `T7` Single Security Pause / Quote-Only,
`R4` Qualification Resolved, `R9` Filing Requirements Satisfied, `C3` Issuer News Not
Forthcoming, `C4` Qualifications Halt Ended (Maintenance Met), `C9` Qualifications Halt
Concluded (Filings Met), `C11` Halt Concluded by Other Regulatory Authority,
`MWCQ` MWCB Resumption, `R1` New Issue Available, `R2` Issue Available,
`IPOQ` IPO Released for Quotation, `IPOE` IPO Positioning Window Extension.
Spaces = reason not available.

## Appendix D - Issue Classification (1-byte Alpha)

`A` ADS, `B` Bond, `C` Common Stock, `F` Depository Receipt, `I` 144A,
`L` Limited Partnership, `N` Notes, `O` Ordinary Share, `P` Preferred Stock,
`Q` Other, `R` Right, `S` Shares of Beneficial Interest, `T` Convertible Debenture,
`U` Unit, `V` Units/Beneficial Interest, `W` Warrant.

## Appendix E - Issue Sub-Type (2-byte Alpha)

`A` Preferred Trust, `AI` Alpha Index ETN, `B` Index Based Derivative, `C` Common Shares,
`CB` Commodity Based Trust, `CF` Commodity Futures Trust, `CL` Commodity-Linked,
`CM` Commodity Index Trust, `CO` CMO, `CT` Currency Trust, `CU` Commodity-Currency-Linked,
`CW` Currency Warrant, `D` Global Depositary Shares, `E` ETF-Portfolio Depositary Receipt,
`EG` Equity GoldShares, `EI` ETN-Equity Index-Linked, `EM` NextShares ETMF,
`EN` Exchange Traded Notes, `EU` Equity Units, `F` HOLDRS, `FI` ETN-Fixed Income-Linked,
`FL` ETN-Futures-Linked, `G` Global Shares, `I` ETF-Index Fund Shares, `IR` Interest Rate,
`IW` Index Warrant, `IX` Index-Linked Exchangeable Notes, `J` Corporate Backed Trust,
`L` Contingent Litigation Right, `LL` LLC Security, `M` Equity-Based Derivative,
`MF` Managed Fund Shares, `ML` ETN-Multi-Factor Index-Linked, `MT` Managed Trust,
`N` NY Registry Shares, `O` Open Ended Mutual Fund, `P` Privately Held, `PP` Poison Pill,
`PU` Partnership Units, `Q` Closed-End Fund, `R` Reg-S, `RC` Redeemable Commodity-Linked,
`RF` ETN-Redeemable Futures-Linked, `RT` REIT, `RU` Redeemable Currency-Linked, `S` SEED,
`SC` Spot Rate Closing, `SI` Spot Rate Intraday, `T` Tracking Stock, `TC` Trust Certificates,
`TU` Trust Units, `U` Portal, `V` Contingent Value Right, `W` Trust Issued Receipts,
`WC` World Currency Option, `X` Trust, `Y` Other, `Z` Not Applicable.

---

## Decoder Implementation Notes

1. **Per UDP packet**: parse the 20-byte MoldUDP64 header; if Message Count is 0 (heartbeat)
   or 0xFFFF (end of session) there is no payload. Otherwise iterate Message Count blocks:
   read 2-byte big-endian length, hand the next `length` bytes to the ITCH decoder, advance.
2. **Per ITCH message**: switch on byte 0 (message type). All messages share the
   locate/tracking/timestamp header at offsets 1/3/5. Validate expected length against the
   Mold block length.
3. **Sequence tracking**: maintain (Session, next expected Sequence Number); each message
   block consumes one sequence number. Gaps mean packet loss.
4. **Timestamps** are 48-bit big-endian nanoseconds since midnight ET - combine with the
   trade date (not in the feed) for absolute time.
5. **Symbol table**: build Stock Locate -> symbol/attributes map from "R" messages at start
   of day; locate codes are not stable across days.
6. **Book building** requires only: A, F, E, C, X, D, U (plus R for symbols and H for state).
   Time-and-sales additionally requires P, Q (printable only) and B.

---

## 7. Flat Parquet Schema (DuckDB / libduckdb)

One row per decoded ITCH message. The schema is flat: it is the union of every column
in the protocol, with fields that have identical meaning across message types sharing
a single column (orderReferenceNumber, stock, matchNumber, shares, price, crossType).
Columns not present in a given message type are NULL, which Parquet stores at
negligible cost (definition levels + dictionary/RLE encoding).

Type mapping rules:

- ITCH Integer 2 byte  -> USMALLINT  (Parquet INT32 / UINT_16)
- ITCH Integer 4 byte  -> UINTEGER   (Parquet INT32 / UINT_32)
- ITCH Integer 8 byte  -> UBIGINT    (Parquet INT64 / UINT_64)
- ITCH Alpha           -> VARCHAR, space padding stripped (Parquet BYTE_ARRAY / UTF8)
- ITCH Price (4)       -> DECIMAL(16,4)  (Parquet INT64 / DECIMAL)
- ITCH Price (8)       -> DECIMAL(20,8)  (Parquet INT64 / DECIMAL)
- Timestamps           -> UBIGINT raw nanoseconds (pcap: since epoch, ITCH: since midnight ET)
- shares is UBIGINT (not UINTEGER) because the Cross Trade "Q" message carries an
  8 byte shares field; the 4 byte shares of A/F/U/P widen losslessly.

```sql
CREATE TABLE itch (
    -- capture / transport layer
    pcapTS                       UBIGINT,        -- pcap timestamp, ns since epoch
    moldSession                  VARCHAR,        -- MoldUDP64 session (10 alpha)
    moldSeqNo                    UBIGINT,        -- MoldUDP64 sequence number of this message
    msgType                      VARCHAR,        -- ITCH message type (1 alpha)

    -- common ITCH header (every message)
    stockLocate                  USMALLINT,
    trackingNumber               USMALLINT,
    timestampNS                  UBIGINT,        -- ns since midnight ET (48-bit)

    -- S: System Event
    eventCode                    VARCHAR,

    -- R: Stock Directory (stock column shared by R H Y L K J h A F P Q I N O)
    stock                        VARCHAR,        -- 8 alpha, space padding stripped
    marketCategory               VARCHAR,
    financialStatusIndicator     VARCHAR,
    roundLotSize                 UINTEGER,
    roundLotsOnly                VARCHAR,
    issueClassification          VARCHAR,
    issueSubType                 VARCHAR,        -- 2 alpha
    authenticity                 VARCHAR,
    shortSaleThresholdIndicator  VARCHAR,
    ipoFlag                      VARCHAR,
    luldReferencePriceTier       VARCHAR,
    etpFlag                      VARCHAR,
    etpLeverageFactor            UINTEGER,
    inverseIndicator             VARCHAR,

    -- H: Stock Trading Action
    tradingState                 VARCHAR,
    tradingActionReason          VARCHAR,        -- 4 alpha

    -- Y: Reg SHO Restriction
    regSHOAction                 VARCHAR,

    -- L: Market Participant Position
    mpid                         VARCHAR,        -- 4 alpha
    primaryMarketMaker           VARCHAR,
    marketMakerMode              VARCHAR,
    marketParticipantState       VARCHAR,

    -- V/W: Market Wide Circuit Breaker
    mwcbLevel1                   DECIMAL(20,8),  -- Price(8)
    mwcbLevel2                   DECIMAL(20,8),
    mwcbLevel3                   DECIMAL(20,8),
    mwcbBreachedLevel            VARCHAR,

    -- K: IPO Quoting Period Update
    ipoQuotationReleaseTime      UINTEGER,       -- seconds since midnight
    ipoQuotationReleaseQualifier VARCHAR,
    ipoPrice                     DECIMAL(16,4),

    -- J: LULD Auction Collar
    auctionCollarReferencePrice  DECIMAL(16,4),
    upperAuctionCollarPrice      DECIMAL(16,4),
    lowerAuctionCollarPrice      DECIMAL(16,4),
    auctionCollarExtension       UINTEGER,

    -- h: Operational Halt
    marketCode                   VARCHAR,
    operationalHaltAction        VARCHAR,

    -- A/F/E/C/X/D/U/P: order book messages
    orderReferenceNumber         UBIGINT,        -- A F E C X D P
    originalOrderReferenceNumber UBIGINT,        -- U
    newOrderReferenceNumber      UBIGINT,        -- U
    buySellIndicator             VARCHAR,        -- A F P
    shares                       UBIGINT,        -- A F U P (4 byte), Q (8 byte)
    price                        DECIMAL(16,4),  -- A F U P
    attribution                  VARCHAR,        -- F, 4 alpha MPID
    executedShares               UINTEGER,       -- E C
    matchNumber                  UBIGINT,        -- E C P Q B
    printable                    VARCHAR,        -- C
    executionPrice               DECIMAL(16,4),  -- C
    cancelledShares              UINTEGER,       -- X

    -- Q: Cross Trade (shares and matchNumber shared above)
    crossPrice                   DECIMAL(16,4),
    crossType                    VARCHAR,        -- Q I

    -- I: Net Order Imbalance Indicator
    pairedShares                 UBIGINT,
    imbalanceShares              UBIGINT,
    imbalanceDirection           VARCHAR,
    farPrice                     DECIMAL(16,4),
    nearPrice                    DECIMAL(16,4),
    currentReferencePrice        DECIMAL(16,4),
    priceVariationIndicator      VARCHAR,

    -- N: Retail Price Improvement Indicator
    interestFlag                 VARCHAR,

    -- O: Direct Listing with Capital Raise
    openEligibilityStatus        VARCHAR,
    minimumAllowablePrice        DECIMAL(16,4),
    maximumAllowablePrice        DECIMAL(16,4),
    nearExecutionPrice           DECIMAL(16,4),
    nearExecutionTimeNS          UBIGINT,
    lowerPriceRangeCollar        DECIMAL(16,4),
    upperPriceRangeCollar        DECIMAL(16,4)
);
```

71 columns total. Schema validated with DuckDB by creating the table and writing an
empty Parquet file; resulting Parquet physical types:

- UBIGINT   -> INT64 / UINT_64
- UINTEGER  -> INT32 / UINT_32
- USMALLINT -> INT32 / UINT_16
- VARCHAR   -> BYTE_ARRAY / UTF8
- DECIMAL   -> INT64 / DECIMAL (16,4) or (20,8)

### Message type -> populated columns

| Type | Columns (beyond pcapTS/moldSession/moldSeqNo/msgType/stockLocate/trackingNumber/timestampNS) |
|------|-----------------------------------------------------------------------------------|
| S    | eventCode |
| R    | stock, marketCategory, financialStatusIndicator, roundLotSize, roundLotsOnly, issueClassification, issueSubType, authenticity, shortSaleThresholdIndicator, ipoFlag, luldReferencePriceTier, etpFlag, etpLeverageFactor, inverseIndicator |
| H    | stock, tradingState, tradingActionReason |
| Y    | stock, regSHOAction |
| L    | mpid, stock, primaryMarketMaker, marketMakerMode, marketParticipantState |
| V    | mwcbLevel1, mwcbLevel2, mwcbLevel3 |
| W    | mwcbBreachedLevel |
| K    | stock, ipoQuotationReleaseTime, ipoQuotationReleaseQualifier, ipoPrice |
| J    | stock, auctionCollarReferencePrice, upperAuctionCollarPrice, lowerAuctionCollarPrice, auctionCollarExtension |
| h    | stock, marketCode, operationalHaltAction |
| A    | orderReferenceNumber, buySellIndicator, shares, stock, price |
| F    | orderReferenceNumber, buySellIndicator, shares, stock, price, attribution |
| E    | orderReferenceNumber, executedShares, matchNumber |
| C    | orderReferenceNumber, executedShares, matchNumber, printable, executionPrice |
| X    | orderReferenceNumber, cancelledShares |
| D    | orderReferenceNumber |
| U    | originalOrderReferenceNumber, newOrderReferenceNumber, shares, price |
| P    | orderReferenceNumber, buySellIndicator, shares, stock, price, matchNumber |
| Q    | shares, stock, crossPrice, matchNumber, crossType |
| B    | matchNumber |
| I    | pairedShares, imbalanceShares, imbalanceDirection, stock, farPrice, nearPrice, currentReferencePrice, crossType, priceVariationIndicator |
| N    | stock, interestFlag |
| O    | stock, openEligibilityStatus, minimumAllowablePrice, maximumAllowablePrice, nearExecutionPrice, nearExecutionTimeNS, lowerPriceRangeCollar, upperPriceRangeCollar |

---

## 8. UDP Multicast Addressing (Subnets / Ports / Groups)

Source: UDP_IP_Address_US_Equity_Market_Data_Feeds.pdf (nasdaqtrader.com FeedMIPS page,
captured 2026-07-04). Nasdaq reserves the right to change these for network and
operational reasons; the live list is at
https://www.nasdaqtrader.com/Trader.aspx?id=FeedMIPS

UDP/IP protocol standard for all TotalView-ITCH 5.0 feeds: MoldUDP64.
RP = PIM Rendezvous Point for the multicast group.

### 8.1 Nasdaq TotalView-ITCH 5.0

| Site                        | Channel / Purpose                          | Group          | Port  | Source IP          |
|-----------------------------|--------------------------------------------|----------------|-------|--------------------|
| Chicago Metro "A" (RP 207.251.255.97)  | Broadcast - Single Channel      | 233.187.20.0   | 18070 | 206.200.95.0/25    |
| Chicago Metro "A"           | Rerequest (unicast)                        | -              | 18170 | 206.200.92.1       |
| Chicago Metro "B" (RP 207.251.255.98)  | Broadcast - Single Channel      | 233.187.20.64  | 18070 | 206.200.95.128/25  |
| New York Metro "A" (RP 207.251.255.46) | Broadcast - Standard Network    | 233.54.12.111  | 26477 | 206.200.127.128/26 |
| New York Metro "A"          | Rerequest - Standard Network (unicast)     | -              | 18170 | 206.200.127.37     |
| New York Metro "B" (RP 207.251.255.56) | Broadcast - Standard Network    | 233.49.196.111 | 26477 | 206.200.127.192/26 |
| New Jersey Metro (RP 207.251.255.6)    | Broadcast - Microwave, Software | 233.86.230.143 | 26477 | 206.200.81.248     |
| New Jersey Metro (RP 207.251.255.6)    | Broadcast - Microwave, FPGA     | 233.86.230.144 | 26400 | 206.200.74.237     |
| New Jersey Metro            | Rerequest - Microwave Network              | not offered    | -     | -                  |
| New York Metro (RP 207.251.255.46)     | ITCH FPGA Broadcast Channel     | 233.54.12.101  | 26400 | 206.200.127.129    |
| Hong Kong Metro "A" (RP 207.251.255.46)| Broadcast - Standard Network    | 233.54.12.111  | 26477 | 206.200.127.128/26 |
| Hong Kong Metro "A"         | Rerequest - Standard Network (unicast)     | -              | 18170 | 206.200.127.37     |
| Hong Kong Metro "B" (RP 207.251.255.56)| Broadcast - Standard Network    | 233.49.196.111 | 26477 | 206.200.127.192/26 |

### 8.2 NTX TotalView-ITCH 5.0 (Nasdaq Texas)

| Site                        | Channel / Purpose                          | Group          | Port  | Source IP          |
|-----------------------------|--------------------------------------------|----------------|-------|--------------------|
| Chicago Metro "A" (RP 207.251.255.97)  | Broadcast - Single Channel      | 233.187.20.32  | 18070 | 206.200.95.0/25    |
| Chicago Metro "A"           | Rerequest (unicast)                        | -              | 18170 | 206.200.92.40      |
| Chicago Metro "B" (RP 207.251.255.98)  | Broadcast - Single Channel      | 233.187.20.40  | 18070 | 206.200.95.128/25  |
| New York Metro "A" (RP 207.251.255.50) | Broadcast - Single Channel      | 233.54.12.40   | 25475 | 206.200.243.224/28 |
| New York Metro "A"          | Rerequest (unicast)                        | -              | 18170 | 206.200.240.37     |
| New York Metro "A"          | NTX ITCH FPGA Broadcast Channel            | 233.54.12.33   | 26400 | 206.200.243.232    |
| New York Metro "B" (RP 207.251.255.60) | Broadcast - Single Channel      | 233.49.196.40  | 25475 | 206.200.243.240/28 |
| New Jersey Metro (RP 207.251.255.6)    | Broadcast - Microwave Network   | 233.86.230.64  | 25475 | 206.200.74.129     |
| New Jersey Metro            | Rerequest - Microwave Network              | not offered    | -     | -                  |

### 8.3 PSX TotalView-ITCH 5.0 (Nasdaq PSX)

| Site                        | Channel / Purpose                          | Group          | Port  | Source IP          |
|-----------------------------|--------------------------------------------|----------------|-------|--------------------|
| Chicago Metro "A" (RP 207.251.255.97)  | Broadcast - Single Channel      | 233.187.20.48  | 18070 | 206.200.95.0/25    |
| Chicago Metro "A"           | Rerequest (unicast)                        | -              | 18170 | 206.200.92.51      |
| Chicago Metro "B" (RP 207.251.255.98)  | Broadcast - Single Channel      | 233.187.20.56  | 18070 | 206.200.95.128/25  |
| New York Metro "A" (RP 207.251.255.49) | Broadcast - Single Channel      | 233.54.12.45   | 26477 | 206.200.63.224/27  |
| New York Metro "A"          | Rerequest (unicast)                        | -              | 18170 | 206.200.63.197     |
| New York Metro "A"          | PSX ITCH FPGA Broadcast Channel            | 233.54.12.123  | 26400 | 206.200.63.237     |
| New York Metro "B" (RP 207.251.255.59) | Broadcast - Single Channel      | 233.49.196.45  | 26477 | 206.200.62.224/27  |

### 8.4 Decoder Filtering Notes

- To identify ITCH 5.0 traffic in a mixed capture, match on UDP destination
  (multicast group, port) pairs from the tables above. The A and B feeds carry
  identical payloads (arbitrate by MoldUDP64 sequence number).
- Multicast group summary for quick filters:
  - Nasdaq ITCH:  233.187.20.0, 233.187.20.64 (port 18070); 233.54.12.111,
    233.49.196.111 (port 26477); 233.54.12.101 (port 26400, FPGA);
    233.86.230.143 (26477), 233.86.230.144 (26400, microwave)
  - NTX ITCH:     233.187.20.32, 233.187.20.40 (18070); 233.54.12.40,
    233.49.196.40 (25475); 233.54.12.33 (26400, FPGA); 233.86.230.64 (25475, microwave)
  - PSX ITCH:     233.187.20.48, 233.187.20.56 (18070); 233.54.12.45,
    233.49.196.45 (26477); 233.54.12.123 (26400, FPGA)
- Rerequest servers are unicast UDP (port 18170 for all three markets); the same
  20-byte MoldUDP64 request packet format applies (section 1.3).
- Source IP subnets are useful for sender validation / reverse path filtering but
  the payload is identical regardless of source.
