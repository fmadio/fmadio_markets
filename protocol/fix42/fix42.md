# FIX 4.2 over TCP - Decoder Reference

Summary of `fix42/fix-42-with_errata_20010501.pdf` (FIX Protocol Version 4.2
with Errata 20010501, FIX Protocol Ltd), `fix42/FIX_4_2_Errata_20010501.pdf`
(errata list) and the QuickFIX FIX 4.2 data dictionary (`fix42/FIX42.xml` -
regenerate the schema tables with `gen_tables.py` when it changes),
containing everything required to decode FIX session and application traffic
from raw TCP packets.

FIX (Financial Information eXchange) 4.2 is a tag=value, ASCII, bidirectional
order entry / trade communication protocol. Unlike the exchange specific
binary protocols (OUCH, ITCH), FIX is a GENERIC protocol: every message is a
flat list of <tag>=<value> pairs, so the decoder does not interpret message
semantics - it explodes every message into ONE PARQUET ROW with ONE COLUMN
PER TAG (fix_1 .. fix_1024). Almost all columns are NULL on any given row;
the flat layout makes ad hoc queries trivial (searching by tag number).

## Protocol Stack

```
Ethernet / VLAN (single or double tagged) / IPv4 / TCP
  +-- FIX message: tag=value pairs separated by SOH (0x01)
        8=FIX.4.2|9=<BodyLength>|35=<MsgType>|...|10=<CheckSum>|
        +-- session (admin) messages: Logon, Heartbeat, ResendRequest, ...
        +-- application messages: NewOrderSingle, ExecutionReport, ...
  +-- Arista 7130 (Metamako) timestamp trailer may follow the TCP payload
```

- TCP based: the decoder consumes REASSEMBLED IN ORDER STREAM SEGMENTS
  (src/tcpstream.c), not datagrams. FIX messages span TCP segment
  boundaries: the decoder buffers partial messages per flow.
- Each direction of the TCP connection is an independent byte stream (and an
  independent flow in the flow table). There is no direction column: the
  parties are identified per message by SenderCompID (fix_49) and
  TargetCompID (fix_56).
- All bytes are ASCII; SOH (0x01) is the field delimiter. Only DATA typed
  fields (section 5) may contain arbitrary bytes including SOH.

---

## 1. Message Framing

Every FIX message is framed by three mandatory fields:

| Field | Tag | Position | Content |
|-------|-----|----------|---------|
| BeginString | 8 | first | `FIX.4.2` - never encrypted, starts the message |
| BodyLength  | 9 | second | byte count from the char after the SOH of tag 9 up to and INCLUDING the SOH before tag 10 |
| CheckSum    | 10 | last | 3 digit decimal (leading zeros), sum mod 256 of every byte up to and including the SOH before `10=` |

MsgType (35) is always the third field. The standard header carries the
session identity (49 SenderCompID, 56 TargetCompID, 34 MsgSeqNum, 52
SendingTime, optional routing/possdup fields); the standard trailer is
optionally 93/89 (SignatureLength/Signature) then always 10 (CheckSum).

Framing algorithm (per flow, on the reassembled stream):

```
1. the buffer must start with "8=FIX"; otherwise resync: scan forward for
   the next "8=FIX", drop the garbage bytes in front of it
2. parse "8=<BeginString><SOH>9=<BodyLength><SOH>" - BodyLength is a
   decimal byte count. sanity cap it (FIX_BODY_MAX); insane = resync
3. total frame length = header prefix + BodyLength + 7 ("10=nnn<SOH>")
4. wait until the buffer holds the whole frame
5. verify the trailer: "10=" at frame end - 7 and SOH at frame end - 1.
   mismatch = BodyLength lied = resync from the next byte
6. checksum: sum of bytes [frame start, frame end - 7) mod 256 vs the tag
   10 value -> hdr_checksumValid (rows are emitted either way)
7. tokenize the tag=value pairs, emit one parquet row, advance
```

A capture that starts mid stream locks onto the first "8=FIX" boundary via
the resync scan (tcpstream.c locks onto the first data packet, the decoder
drops the partial message in front of the first boundary).

---

## 2. Session Layer (admin messages)

FIX sequence numbers are EXPLICIT: every message carries MsgSeqNum (34),
numbered from 1 per session per direction, reset daily or via Logon/
SequenceReset. Gap recovery is ResendRequest (35=2) + retransmits flagged
PossDupFlag (43=Y) with OrigSendingTime (122); SequenceReset-GapFill (35=4,
123=Y) skips admin messages in a replay. The decoder does NOT track or
validate sequence numbers - every message on the wire (originals and
PossDup retransmits alike) becomes a row; gap/dup analysis is a parquet
query on fix_34 / fix_43.

Session establishment is Logon (35=A) with EncryptMethod (98) and
HeartBtInt (108); the decoder stores but never interprets encryption -
SecureData (91) wrapped bodies decode as a normal message with tag 91 (the
encrypted blob) populated. Heartbeat (35=0) / TestRequest (35=1) /
Logout (35=5) all emit rows: captures with no order flow still yield full
session observability.

### Message types (35)

| MsgType | Message | Category |
|---------|---------|----------|
| 0 | Heartbeat | admin |
| 1 | TestRequest | admin |
| 2 | ResendRequest | admin |
| 3 | Reject | admin |
| 4 | SequenceReset | admin |
| 5 | Logout | admin |
| 6 | IOI | app |
| 7 | Advertisement | app |
| 8 | ExecutionReport | app |
| 9 | OrderCancelReject | app |
| A | Logon | admin |
| B | News | app |
| C | Email | app |
| D | NewOrderSingle | app |
| E | NewOrderList | app |
| F | OrderCancelRequest | app |
| G | OrderCancelReplaceRequest | app |
| H | OrderStatusRequest | app |
| J | Allocation | app |
| K | ListCancelRequest | app |
| L | ListExecute | app |
| M | ListStatusRequest | app |
| N | ListStatus | app |
| P | AllocationInstructionAck | app |
| Q | DontKnowTrade | app |
| R | QuoteRequest | app |
| S | Quote | app |
| T | SettlementInstructions | app |
| V | MarketDataRequest | app |
| W | MarketDataSnapshotFullRefresh | app |
| X | MarketDataIncrementalRefresh | app |
| Y | MarketDataRequestReject | app |
| Z | QuoteCancel | app |
| a | QuoteStatusRequest | app |
| b | QuoteAcknowledgement | app |
| c | SecurityDefinitionRequest | app |
| d | SecurityDefinition | app |
| e | SecurityStatusRequest | app |
| f | SecurityStatus | app |
| g | TradingSessionStatusRequest | app |
| h | TradingSessionStatus | app |
| i | MassQuote | app |
| j | BusinessMessageReject | app |
| k | BidRequest | app |
| l | BidResponse | app |
| m | ListStrikePrice | app |

---

## 3. Data Types -> Parquet Storage

FIX values are ASCII text; the dictionary types map onto three storage
classes. Numeric parse failures (malformed values) store NULL.

| FIX Type | Parquet | Notes |
|----------|---------|-------|
| INT, DAYOFMONTH | BIGINT | strtoll |
| LENGTH | BIGINT | also arms the byte length of the following DATA field |
| PRICE, QTY, AMT, FLOAT, PRICEOFFSET | DOUBLE | strtod; FIX qtys may be fractional |
| STRING, CHAR, BOOLEAN, CURRENCY, EXCHANGE, MULTIPLEVALUESTRING | VARCHAR | raw value |
| UTCTIMESTAMP, UTCDATE, UTCTIMEONLY, LOCALMKTDATE, MONTHYEAR | VARCHAR | e.g. `20010501-14:30:05.123`; parse in queries with strptime |
| DATA | VARCHAR | raw bytes, length from the paired LENGTH tag; non printable bytes stored as `.` |
| undefined tags (gaps + 447..1024) | VARCHAR | custom/user tags |

Timestamps stay VARCHAR because FIX carries no epoch values - convert in
duckdb: `strptime(fix_52, '%Y%m%d-%H:%M:%S.%g')`.

### Key enums

**Side (54)**: `1`=BUY, `2`=SELL, `3`=BUY_MINUS, `4`=SELL_PLUS, `5`=SELL_SHORT, `6`=SELL_SHORT_EXEMPT, `7`=UNDISCLOSED, `8`=CROSS, `9`=CROSS_SHORT

**OrdType (40)**: `1`=MARKET, `2`=LIMIT, `3`=STOP, `4`=STOP_LIMIT, `5`=MARKET_ON_CLOSE, `6`=WITH_OR_WITHOUT, `7`=LIMIT_OR_BETTER, `8`=LIMIT_WITH_OR_WITHOUT, `9`=ON_BASIS, `A`=ON_CLOSE, `B`=LIMIT_ON_CLOSE, `C`=FOREX_MARKET, `D`=PREVIOUSLY_QUOTED, `E`=PREVIOUSLY_INDICATED, `F`=FOREX_LIMIT, `G`=FOREX_SWAP, `H`=FOREX_PREVIOUSLY_QUOTED, `I`=FUNARI, `P`=PEGGED

**OrdStatus (39)**: `0`=NEW, `1`=PARTIALLY_FILLED, `2`=FILLED, `3`=DONE_FOR_DAY, `4`=CANCELED, `5`=REPLACED, `6`=PENDING_CANCEL, `7`=STOPPED, `8`=REJECTED, `9`=SUSPENDED, `A`=PENDING_NEW, `B`=CALCULATED, `C`=EXPIRED, `D`=ACCEPTED_FOR_BIDDING, `E`=PENDING_REPLACE

**ExecType (150)**: `0`=NEW, `1`=PARTIAL_FILL, `2`=FILL, `3`=DONE_FOR_DAY, `4`=CANCELED, `5`=REPLACED, `6`=PENDING_CANCEL, `7`=STOPPED, `8`=REJECTED, `9`=SUSPENDED, `A`=PENDING_NEW, `B`=CALCULATED, `C`=EXPIRED, `D`=RESTATED, `E`=PENDING_REPLACE

**ExecTransType (20)**: `0`=NEW, `1`=CANCEL, `2`=CORRECT, `3`=STATUS

**TimeInForce (59)**: `0`=DAY, `1`=GOOD_TILL_CANCEL, `2`=AT_THE_OPENING, `3`=IMMEDIATE_OR_CANCEL, `4`=FILL_OR_KILL, `5`=GOOD_TILL_CROSSING, `6`=GOOD_TILL_DATE

Full enums for every field are in FIX42.xml.

---

## 4. Tag Dictionary (405 defined tags)

One parquet column per tag: `fix_<tag>`, tags 1..1024. The 405 tags below
are defined by FIX 4.2; the remaining columns (gaps and 447..1024) are
VARCHAR catch-alls for custom/user tags. Tags above 1024 are dropped and
counted in hdr_overflowTagCount.

| Tag | Name | FIX Type | Column | Parquet Type |
|-----|------|----------|--------|--------------|
| 1 | Account | STRING | fix_1 | VARCHAR |
| 2 | AdvId | STRING | fix_2 | VARCHAR |
| 3 | AdvRefID | STRING | fix_3 | VARCHAR |
| 4 | AdvSide | CHAR | fix_4 | VARCHAR |
| 5 | AdvTransType | STRING | fix_5 | VARCHAR |
| 6 | AvgPx | PRICE | fix_6 | DOUBLE |
| 7 | BeginSeqNo | INT | fix_7 | BIGINT |
| 8 | BeginString | STRING | fix_8 | VARCHAR |
| 9 | BodyLength | INT | fix_9 | BIGINT |
| 10 | CheckSum | STRING | fix_10 | VARCHAR |
| 11 | ClOrdID | STRING | fix_11 | VARCHAR |
| 12 | Commission | AMT | fix_12 | DOUBLE |
| 13 | CommType | CHAR | fix_13 | VARCHAR |
| 14 | CumQty | QTY | fix_14 | DOUBLE |
| 15 | Currency | CURRENCY | fix_15 | VARCHAR |
| 16 | EndSeqNo | INT | fix_16 | BIGINT |
| 17 | ExecID | STRING | fix_17 | VARCHAR |
| 18 | ExecInst | MULTIPLEVALUESTRING | fix_18 | VARCHAR |
| 19 | ExecRefID | STRING | fix_19 | VARCHAR |
| 20 | ExecTransType | CHAR | fix_20 | VARCHAR |
| 21 | HandlInst | CHAR | fix_21 | VARCHAR |
| 22 | IDSource | STRING | fix_22 | VARCHAR |
| 23 | IOIid | STRING | fix_23 | VARCHAR |
| 24 | IOIOthSvc | CHAR | fix_24 | VARCHAR |
| 25 | IOIQltyInd | CHAR | fix_25 | VARCHAR |
| 26 | IOIRefID | STRING | fix_26 | VARCHAR |
| 27 | IOIShares | STRING | fix_27 | VARCHAR |
| 28 | IOITransType | CHAR | fix_28 | VARCHAR |
| 29 | LastCapacity | CHAR | fix_29 | VARCHAR |
| 30 | LastMkt | EXCHANGE | fix_30 | VARCHAR |
| 31 | LastPx | PRICE | fix_31 | DOUBLE |
| 32 | LastShares | QTY | fix_32 | DOUBLE |
| 33 | LinesOfText | INT | fix_33 | BIGINT |
| 34 | MsgSeqNum | INT | fix_34 | BIGINT |
| 35 | MsgType | STRING | fix_35 | VARCHAR |
| 36 | NewSeqNo | INT | fix_36 | BIGINT |
| 37 | OrderID | STRING | fix_37 | VARCHAR |
| 38 | OrderQty | QTY | fix_38 | DOUBLE |
| 39 | OrdStatus | CHAR | fix_39 | VARCHAR |
| 40 | OrdType | CHAR | fix_40 | VARCHAR |
| 41 | OrigClOrdID | STRING | fix_41 | VARCHAR |
| 42 | OrigTime | UTCTIMESTAMP | fix_42 | VARCHAR |
| 43 | PossDupFlag | BOOLEAN | fix_43 | VARCHAR |
| 44 | Price | PRICE | fix_44 | DOUBLE |
| 45 | RefSeqNum | INT | fix_45 | BIGINT |
| 46 | RelatdSym | STRING | fix_46 | VARCHAR |
| 47 | Rule80A | CHAR | fix_47 | VARCHAR |
| 48 | SecurityID | STRING | fix_48 | VARCHAR |
| 49 | SenderCompID | STRING | fix_49 | VARCHAR |
| 50 | SenderSubID | STRING | fix_50 | VARCHAR |
| 51 | SendingDate | LOCALMKTDATE | fix_51 | VARCHAR |
| 52 | SendingTime | UTCTIMESTAMP | fix_52 | VARCHAR |
| 53 | Shares | QTY | fix_53 | DOUBLE |
| 54 | Side | CHAR | fix_54 | VARCHAR |
| 55 | Symbol | STRING | fix_55 | VARCHAR |
| 56 | TargetCompID | STRING | fix_56 | VARCHAR |
| 57 | TargetSubID | STRING | fix_57 | VARCHAR |
| 58 | Text | STRING | fix_58 | VARCHAR |
| 59 | TimeInForce | CHAR | fix_59 | VARCHAR |
| 60 | TransactTime | UTCTIMESTAMP | fix_60 | VARCHAR |
| 61 | Urgency | CHAR | fix_61 | VARCHAR |
| 62 | ValidUntilTime | UTCTIMESTAMP | fix_62 | VARCHAR |
| 63 | SettlmntTyp | CHAR | fix_63 | VARCHAR |
| 64 | FutSettDate | LOCALMKTDATE | fix_64 | VARCHAR |
| 65 | SymbolSfx | STRING | fix_65 | VARCHAR |
| 66 | ListID | STRING | fix_66 | VARCHAR |
| 67 | ListSeqNo | INT | fix_67 | BIGINT |
| 68 | TotNoOrders | INT | fix_68 | BIGINT |
| 69 | ListExecInst | STRING | fix_69 | VARCHAR |
| 70 | AllocID | STRING | fix_70 | VARCHAR |
| 71 | AllocTransType | CHAR | fix_71 | VARCHAR |
| 72 | RefAllocID | STRING | fix_72 | VARCHAR |
| 73 | NoOrders | INT | fix_73 | BIGINT |
| 74 | AvgPrxPrecision | INT | fix_74 | BIGINT |
| 75 | TradeDate | LOCALMKTDATE | fix_75 | VARCHAR |
| 76 | ExecBroker | STRING | fix_76 | VARCHAR |
| 77 | OpenClose | CHAR | fix_77 | VARCHAR |
| 78 | NoAllocs | INT | fix_78 | BIGINT |
| 79 | AllocAccount | STRING | fix_79 | VARCHAR |
| 80 | AllocShares | QTY | fix_80 | DOUBLE |
| 81 | ProcessCode | CHAR | fix_81 | VARCHAR |
| 82 | NoRpts | INT | fix_82 | BIGINT |
| 83 | RptSeq | INT | fix_83 | BIGINT |
| 84 | CxlQty | QTY | fix_84 | DOUBLE |
| 85 | NoDlvyInst | INT | fix_85 | BIGINT |
| 86 | DlvyInst | STRING | fix_86 | VARCHAR |
| 87 | AllocStatus | INT | fix_87 | BIGINT |
| 88 | AllocRejCode | INT | fix_88 | BIGINT |
| 89 | Signature | DATA | fix_89 | VARCHAR |
| 90 | SecureDataLen | LENGTH | fix_90 | BIGINT |
| 91 | SecureData | DATA | fix_91 | VARCHAR |
| 92 | BrokerOfCredit | STRING | fix_92 | VARCHAR |
| 93 | SignatureLength | LENGTH | fix_93 | BIGINT |
| 94 | EmailType | CHAR | fix_94 | VARCHAR |
| 95 | RawDataLength | LENGTH | fix_95 | BIGINT |
| 96 | RawData | DATA | fix_96 | VARCHAR |
| 97 | PossResend | BOOLEAN | fix_97 | VARCHAR |
| 98 | EncryptMethod | INT | fix_98 | BIGINT |
| 99 | StopPx | PRICE | fix_99 | DOUBLE |
| 100 | ExDestination | EXCHANGE | fix_100 | VARCHAR |
| 102 | CxlRejReason | INT | fix_102 | BIGINT |
| 103 | OrdRejReason | INT | fix_103 | BIGINT |
| 104 | IOIQualifier | CHAR | fix_104 | VARCHAR |
| 105 | WaveNo | STRING | fix_105 | VARCHAR |
| 106 | Issuer | STRING | fix_106 | VARCHAR |
| 107 | SecurityDesc | STRING | fix_107 | VARCHAR |
| 108 | HeartBtInt | INT | fix_108 | BIGINT |
| 109 | ClientID | STRING | fix_109 | VARCHAR |
| 110 | MinQty | QTY | fix_110 | DOUBLE |
| 111 | MaxFloor | QTY | fix_111 | DOUBLE |
| 112 | TestReqID | STRING | fix_112 | VARCHAR |
| 113 | ReportToExch | BOOLEAN | fix_113 | VARCHAR |
| 114 | LocateReqd | BOOLEAN | fix_114 | VARCHAR |
| 115 | OnBehalfOfCompID | STRING | fix_115 | VARCHAR |
| 116 | OnBehalfOfSubID | STRING | fix_116 | VARCHAR |
| 117 | QuoteID | STRING | fix_117 | VARCHAR |
| 118 | NetMoney | AMT | fix_118 | DOUBLE |
| 119 | SettlCurrAmt | AMT | fix_119 | DOUBLE |
| 120 | SettlCurrency | CURRENCY | fix_120 | VARCHAR |
| 121 | ForexReq | BOOLEAN | fix_121 | VARCHAR |
| 122 | OrigSendingTime | UTCTIMESTAMP | fix_122 | VARCHAR |
| 123 | GapFillFlag | BOOLEAN | fix_123 | VARCHAR |
| 124 | NoExecs | INT | fix_124 | BIGINT |
| 125 | CxlType | CHAR | fix_125 | VARCHAR |
| 126 | ExpireTime | UTCTIMESTAMP | fix_126 | VARCHAR |
| 127 | DKReason | CHAR | fix_127 | VARCHAR |
| 128 | DeliverToCompID | STRING | fix_128 | VARCHAR |
| 129 | DeliverToSubID | STRING | fix_129 | VARCHAR |
| 130 | IOINaturalFlag | BOOLEAN | fix_130 | VARCHAR |
| 131 | QuoteReqID | STRING | fix_131 | VARCHAR |
| 132 | BidPx | PRICE | fix_132 | DOUBLE |
| 133 | OfferPx | PRICE | fix_133 | DOUBLE |
| 134 | BidSize | QTY | fix_134 | DOUBLE |
| 135 | OfferSize | QTY | fix_135 | DOUBLE |
| 136 | NoMiscFees | INT | fix_136 | BIGINT |
| 137 | MiscFeeAmt | AMT | fix_137 | DOUBLE |
| 138 | MiscFeeCurr | CURRENCY | fix_138 | VARCHAR |
| 139 | MiscFeeType | CHAR | fix_139 | VARCHAR |
| 140 | PrevClosePx | PRICE | fix_140 | DOUBLE |
| 141 | ResetSeqNumFlag | BOOLEAN | fix_141 | VARCHAR |
| 142 | SenderLocationID | STRING | fix_142 | VARCHAR |
| 143 | TargetLocationID | STRING | fix_143 | VARCHAR |
| 144 | OnBehalfOfLocationID | STRING | fix_144 | VARCHAR |
| 145 | DeliverToLocationID | STRING | fix_145 | VARCHAR |
| 146 | NoRelatedSym | INT | fix_146 | BIGINT |
| 147 | Subject | STRING | fix_147 | VARCHAR |
| 148 | Headline | STRING | fix_148 | VARCHAR |
| 149 | URLLink | STRING | fix_149 | VARCHAR |
| 150 | ExecType | CHAR | fix_150 | VARCHAR |
| 151 | LeavesQty | QTY | fix_151 | DOUBLE |
| 152 | CashOrderQty | QTY | fix_152 | DOUBLE |
| 153 | AllocAvgPx | PRICE | fix_153 | DOUBLE |
| 154 | AllocNetMoney | AMT | fix_154 | DOUBLE |
| 155 | SettlCurrFxRate | FLOAT | fix_155 | DOUBLE |
| 156 | SettlCurrFxRateCalc | CHAR | fix_156 | VARCHAR |
| 157 | NumDaysInterest | INT | fix_157 | BIGINT |
| 158 | AccruedInterestRate | FLOAT | fix_158 | DOUBLE |
| 159 | AccruedInterestAmt | AMT | fix_159 | DOUBLE |
| 160 | SettlInstMode | CHAR | fix_160 | VARCHAR |
| 161 | AllocText | STRING | fix_161 | VARCHAR |
| 162 | SettlInstID | STRING | fix_162 | VARCHAR |
| 163 | SettlInstTransType | CHAR | fix_163 | VARCHAR |
| 164 | EmailThreadID | STRING | fix_164 | VARCHAR |
| 165 | SettlInstSource | CHAR | fix_165 | VARCHAR |
| 166 | SettlLocation | STRING | fix_166 | VARCHAR |
| 167 | SecurityType | STRING | fix_167 | VARCHAR |
| 168 | EffectiveTime | UTCTIMESTAMP | fix_168 | VARCHAR |
| 169 | StandInstDbType | INT | fix_169 | BIGINT |
| 170 | StandInstDbName | STRING | fix_170 | VARCHAR |
| 171 | StandInstDbID | STRING | fix_171 | VARCHAR |
| 172 | SettlDeliveryType | INT | fix_172 | BIGINT |
| 173 | SettlDepositoryCode | STRING | fix_173 | VARCHAR |
| 174 | SettlBrkrCode | STRING | fix_174 | VARCHAR |
| 175 | SettlInstCode | STRING | fix_175 | VARCHAR |
| 176 | SecuritySettlAgentName | STRING | fix_176 | VARCHAR |
| 177 | SecuritySettlAgentCode | STRING | fix_177 | VARCHAR |
| 178 | SecuritySettlAgentAcctNum | STRING | fix_178 | VARCHAR |
| 179 | SecuritySettlAgentAcctName | STRING | fix_179 | VARCHAR |
| 180 | SecuritySettlAgentContactName | STRING | fix_180 | VARCHAR |
| 181 | SecuritySettlAgentContactPhone | STRING | fix_181 | VARCHAR |
| 182 | CashSettlAgentName | STRING | fix_182 | VARCHAR |
| 183 | CashSettlAgentCode | STRING | fix_183 | VARCHAR |
| 184 | CashSettlAgentAcctNum | STRING | fix_184 | VARCHAR |
| 185 | CashSettlAgentAcctName | STRING | fix_185 | VARCHAR |
| 186 | CashSettlAgentContactName | STRING | fix_186 | VARCHAR |
| 187 | CashSettlAgentContactPhone | STRING | fix_187 | VARCHAR |
| 188 | BidSpotRate | PRICE | fix_188 | DOUBLE |
| 189 | BidForwardPoints | PRICEOFFSET | fix_189 | DOUBLE |
| 190 | OfferSpotRate | PRICE | fix_190 | DOUBLE |
| 191 | OfferForwardPoints | PRICEOFFSET | fix_191 | DOUBLE |
| 192 | OrderQty2 | QTY | fix_192 | DOUBLE |
| 193 | FutSettDate2 | LOCALMKTDATE | fix_193 | VARCHAR |
| 194 | LastSpotRate | PRICE | fix_194 | DOUBLE |
| 195 | LastForwardPoints | PRICEOFFSET | fix_195 | DOUBLE |
| 196 | AllocLinkID | STRING | fix_196 | VARCHAR |
| 197 | AllocLinkType | INT | fix_197 | BIGINT |
| 198 | SecondaryOrderID | STRING | fix_198 | VARCHAR |
| 199 | NoIOIQualifiers | INT | fix_199 | BIGINT |
| 200 | MaturityMonthYear | MONTHYEAR | fix_200 | VARCHAR |
| 201 | PutOrCall | INT | fix_201 | BIGINT |
| 202 | StrikePrice | PRICE | fix_202 | DOUBLE |
| 203 | CoveredOrUncovered | INT | fix_203 | BIGINT |
| 204 | CustomerOrFirm | INT | fix_204 | BIGINT |
| 205 | MaturityDay | DAYOFMONTH | fix_205 | BIGINT |
| 206 | OptAttribute | CHAR | fix_206 | VARCHAR |
| 207 | SecurityExchange | EXCHANGE | fix_207 | VARCHAR |
| 208 | NotifyBrokerOfCredit | BOOLEAN | fix_208 | VARCHAR |
| 209 | AllocHandlInst | INT | fix_209 | BIGINT |
| 210 | MaxShow | QTY | fix_210 | DOUBLE |
| 211 | PegDifference | PRICEOFFSET | fix_211 | DOUBLE |
| 212 | XmlDataLen | LENGTH | fix_212 | BIGINT |
| 213 | XmlData | DATA | fix_213 | VARCHAR |
| 214 | SettlInstRefID | STRING | fix_214 | VARCHAR |
| 215 | NoRoutingIDs | INT | fix_215 | BIGINT |
| 216 | RoutingType | INT | fix_216 | BIGINT |
| 217 | RoutingID | STRING | fix_217 | VARCHAR |
| 218 | SpreadToBenchmark | PRICEOFFSET | fix_218 | DOUBLE |
| 219 | Benchmark | CHAR | fix_219 | VARCHAR |
| 223 | CouponRate | FLOAT | fix_223 | DOUBLE |
| 231 | ContractMultiplier | FLOAT | fix_231 | DOUBLE |
| 262 | MDReqID | STRING | fix_262 | VARCHAR |
| 263 | SubscriptionRequestType | CHAR | fix_263 | VARCHAR |
| 264 | MarketDepth | INT | fix_264 | BIGINT |
| 265 | MDUpdateType | INT | fix_265 | BIGINT |
| 266 | AggregatedBook | BOOLEAN | fix_266 | VARCHAR |
| 267 | NoMDEntryTypes | INT | fix_267 | BIGINT |
| 268 | NoMDEntries | INT | fix_268 | BIGINT |
| 269 | MDEntryType | CHAR | fix_269 | VARCHAR |
| 270 | MDEntryPx | PRICE | fix_270 | DOUBLE |
| 271 | MDEntrySize | QTY | fix_271 | DOUBLE |
| 272 | MDEntryDate | UTCDATE | fix_272 | VARCHAR |
| 273 | MDEntryTime | UTCTIMEONLY | fix_273 | VARCHAR |
| 274 | TickDirection | CHAR | fix_274 | VARCHAR |
| 275 | MDMkt | EXCHANGE | fix_275 | VARCHAR |
| 276 | QuoteCondition | MULTIPLEVALUESTRING | fix_276 | VARCHAR |
| 277 | TradeCondition | MULTIPLEVALUESTRING | fix_277 | VARCHAR |
| 278 | MDEntryID | STRING | fix_278 | VARCHAR |
| 279 | MDUpdateAction | CHAR | fix_279 | VARCHAR |
| 280 | MDEntryRefID | STRING | fix_280 | VARCHAR |
| 281 | MDReqRejReason | CHAR | fix_281 | VARCHAR |
| 282 | MDEntryOriginator | STRING | fix_282 | VARCHAR |
| 283 | LocationID | STRING | fix_283 | VARCHAR |
| 284 | DeskID | STRING | fix_284 | VARCHAR |
| 285 | DeleteReason | CHAR | fix_285 | VARCHAR |
| 286 | OpenCloseSettleFlag | CHAR | fix_286 | VARCHAR |
| 287 | SellerDays | INT | fix_287 | BIGINT |
| 288 | MDEntryBuyer | STRING | fix_288 | VARCHAR |
| 289 | MDEntrySeller | STRING | fix_289 | VARCHAR |
| 290 | MDEntryPositionNo | INT | fix_290 | BIGINT |
| 291 | FinancialStatus | CHAR | fix_291 | VARCHAR |
| 292 | CorporateAction | CHAR | fix_292 | VARCHAR |
| 293 | DefBidSize | QTY | fix_293 | DOUBLE |
| 294 | DefOfferSize | QTY | fix_294 | DOUBLE |
| 295 | NoQuoteEntries | INT | fix_295 | BIGINT |
| 296 | NoQuoteSets | INT | fix_296 | BIGINT |
| 297 | QuoteStatus | INT | fix_297 | BIGINT |
| 298 | QuoteCancelType | INT | fix_298 | BIGINT |
| 299 | QuoteEntryID | STRING | fix_299 | VARCHAR |
| 300 | QuoteRejectReason | INT | fix_300 | BIGINT |
| 301 | QuoteResponseLevel | INT | fix_301 | BIGINT |
| 302 | QuoteSetID | STRING | fix_302 | VARCHAR |
| 303 | QuoteRequestType | INT | fix_303 | BIGINT |
| 304 | TotQuoteEntries | INT | fix_304 | BIGINT |
| 305 | UnderlyingIDSource | STRING | fix_305 | VARCHAR |
| 306 | UnderlyingIssuer | STRING | fix_306 | VARCHAR |
| 307 | UnderlyingSecurityDesc | STRING | fix_307 | VARCHAR |
| 308 | UnderlyingSecurityExchange | EXCHANGE | fix_308 | VARCHAR |
| 309 | UnderlyingSecurityID | STRING | fix_309 | VARCHAR |
| 310 | UnderlyingSecurityType | STRING | fix_310 | VARCHAR |
| 311 | UnderlyingSymbol | STRING | fix_311 | VARCHAR |
| 312 | UnderlyingSymbolSfx | STRING | fix_312 | VARCHAR |
| 313 | UnderlyingMaturityMonthYear | MONTHYEAR | fix_313 | VARCHAR |
| 314 | UnderlyingMaturityDay | DAYOFMONTH | fix_314 | BIGINT |
| 315 | UnderlyingPutOrCall | INT | fix_315 | BIGINT |
| 316 | UnderlyingStrikePrice | PRICE | fix_316 | DOUBLE |
| 317 | UnderlyingOptAttribute | CHAR | fix_317 | VARCHAR |
| 318 | UnderlyingCurrency | CURRENCY | fix_318 | VARCHAR |
| 319 | RatioQty | QTY | fix_319 | DOUBLE |
| 320 | SecurityReqID | STRING | fix_320 | VARCHAR |
| 321 | SecurityRequestType | INT | fix_321 | BIGINT |
| 322 | SecurityResponseID | STRING | fix_322 | VARCHAR |
| 323 | SecurityResponseType | INT | fix_323 | BIGINT |
| 324 | SecurityStatusReqID | STRING | fix_324 | VARCHAR |
| 325 | UnsolicitedIndicator | BOOLEAN | fix_325 | VARCHAR |
| 326 | SecurityTradingStatus | INT | fix_326 | BIGINT |
| 327 | HaltReasonChar | CHAR | fix_327 | VARCHAR |
| 328 | InViewOfCommon | BOOLEAN | fix_328 | VARCHAR |
| 329 | DueToRelated | BOOLEAN | fix_329 | VARCHAR |
| 330 | BuyVolume | QTY | fix_330 | DOUBLE |
| 331 | SellVolume | QTY | fix_331 | DOUBLE |
| 332 | HighPx | PRICE | fix_332 | DOUBLE |
| 333 | LowPx | PRICE | fix_333 | DOUBLE |
| 334 | Adjustment | INT | fix_334 | BIGINT |
| 335 | TradSesReqID | STRING | fix_335 | VARCHAR |
| 336 | TradingSessionID | STRING | fix_336 | VARCHAR |
| 337 | ContraTrader | STRING | fix_337 | VARCHAR |
| 338 | TradSesMethod | INT | fix_338 | BIGINT |
| 339 | TradSesMode | INT | fix_339 | BIGINT |
| 340 | TradSesStatus | INT | fix_340 | BIGINT |
| 341 | TradSesStartTime | UTCTIMESTAMP | fix_341 | VARCHAR |
| 342 | TradSesOpenTime | UTCTIMESTAMP | fix_342 | VARCHAR |
| 343 | TradSesPreCloseTime | UTCTIMESTAMP | fix_343 | VARCHAR |
| 344 | TradSesCloseTime | UTCTIMESTAMP | fix_344 | VARCHAR |
| 345 | TradSesEndTime | UTCTIMESTAMP | fix_345 | VARCHAR |
| 346 | NumberOfOrders | INT | fix_346 | BIGINT |
| 347 | MessageEncoding | STRING | fix_347 | VARCHAR |
| 348 | EncodedIssuerLen | LENGTH | fix_348 | BIGINT |
| 349 | EncodedIssuer | DATA | fix_349 | VARCHAR |
| 350 | EncodedSecurityDescLen | LENGTH | fix_350 | BIGINT |
| 351 | EncodedSecurityDesc | DATA | fix_351 | VARCHAR |
| 352 | EncodedListExecInstLen | LENGTH | fix_352 | BIGINT |
| 353 | EncodedListExecInst | DATA | fix_353 | VARCHAR |
| 354 | EncodedTextLen | LENGTH | fix_354 | BIGINT |
| 355 | EncodedText | DATA | fix_355 | VARCHAR |
| 356 | EncodedSubjectLen | LENGTH | fix_356 | BIGINT |
| 357 | EncodedSubject | DATA | fix_357 | VARCHAR |
| 358 | EncodedHeadlineLen | LENGTH | fix_358 | BIGINT |
| 359 | EncodedHeadline | DATA | fix_359 | VARCHAR |
| 360 | EncodedAllocTextLen | LENGTH | fix_360 | BIGINT |
| 361 | EncodedAllocText | DATA | fix_361 | VARCHAR |
| 362 | EncodedUnderlyingIssuerLen | LENGTH | fix_362 | BIGINT |
| 363 | EncodedUnderlyingIssuer | DATA | fix_363 | VARCHAR |
| 364 | EncodedUnderlyingSecurityDescLen | LENGTH | fix_364 | BIGINT |
| 365 | EncodedUnderlyingSecurityDesc | DATA | fix_365 | VARCHAR |
| 366 | AllocPrice | PRICE | fix_366 | DOUBLE |
| 367 | QuoteSetValidUntilTime | UTCTIMESTAMP | fix_367 | VARCHAR |
| 368 | QuoteEntryRejectReason | INT | fix_368 | BIGINT |
| 369 | LastMsgSeqNumProcessed | INT | fix_369 | BIGINT |
| 370 | OnBehalfOfSendingTime | UTCTIMESTAMP | fix_370 | VARCHAR |
| 371 | RefTagID | INT | fix_371 | BIGINT |
| 372 | RefMsgType | STRING | fix_372 | VARCHAR |
| 373 | SessionRejectReason | INT | fix_373 | BIGINT |
| 374 | BidRequestTransType | CHAR | fix_374 | VARCHAR |
| 375 | ContraBroker | STRING | fix_375 | VARCHAR |
| 376 | ComplianceID | STRING | fix_376 | VARCHAR |
| 377 | SolicitedFlag | BOOLEAN | fix_377 | VARCHAR |
| 378 | ExecRestatementReason | INT | fix_378 | BIGINT |
| 379 | BusinessRejectRefID | STRING | fix_379 | VARCHAR |
| 380 | BusinessRejectReason | INT | fix_380 | BIGINT |
| 381 | GrossTradeAmt | AMT | fix_381 | DOUBLE |
| 382 | NoContraBrokers | INT | fix_382 | BIGINT |
| 383 | MaxMessageSize | INT | fix_383 | BIGINT |
| 384 | NoMsgTypes | INT | fix_384 | BIGINT |
| 385 | MsgDirection | CHAR | fix_385 | VARCHAR |
| 386 | NoTradingSessions | INT | fix_386 | BIGINT |
| 387 | TotalVolumeTraded | QTY | fix_387 | DOUBLE |
| 388 | DiscretionInst | CHAR | fix_388 | VARCHAR |
| 389 | DiscretionOffset | PRICEOFFSET | fix_389 | DOUBLE |
| 390 | BidID | STRING | fix_390 | VARCHAR |
| 391 | ClientBidID | STRING | fix_391 | VARCHAR |
| 392 | ListName | STRING | fix_392 | VARCHAR |
| 393 | TotalNumSecurities | INT | fix_393 | BIGINT |
| 394 | BidType | INT | fix_394 | BIGINT |
| 395 | NumTickets | INT | fix_395 | BIGINT |
| 396 | SideValue1 | AMT | fix_396 | DOUBLE |
| 397 | SideValue2 | AMT | fix_397 | DOUBLE |
| 398 | NoBidDescriptors | INT | fix_398 | BIGINT |
| 399 | BidDescriptorType | INT | fix_399 | BIGINT |
| 400 | BidDescriptor | STRING | fix_400 | VARCHAR |
| 401 | SideValueInd | INT | fix_401 | BIGINT |
| 402 | LiquidityPctLow | FLOAT | fix_402 | DOUBLE |
| 403 | LiquidityPctHigh | FLOAT | fix_403 | DOUBLE |
| 404 | LiquidityValue | AMT | fix_404 | DOUBLE |
| 405 | EFPTrackingError | FLOAT | fix_405 | DOUBLE |
| 406 | FairValue | AMT | fix_406 | DOUBLE |
| 407 | OutsideIndexPct | FLOAT | fix_407 | DOUBLE |
| 408 | ValueOfFutures | AMT | fix_408 | DOUBLE |
| 409 | LiquidityIndType | INT | fix_409 | BIGINT |
| 410 | WtAverageLiquidity | FLOAT | fix_410 | DOUBLE |
| 411 | ExchangeForPhysical | BOOLEAN | fix_411 | VARCHAR |
| 412 | OutMainCntryUIndex | AMT | fix_412 | DOUBLE |
| 413 | CrossPercent | FLOAT | fix_413 | DOUBLE |
| 414 | ProgRptReqs | INT | fix_414 | BIGINT |
| 415 | ProgPeriodInterval | INT | fix_415 | BIGINT |
| 416 | IncTaxInd | INT | fix_416 | BIGINT |
| 417 | NumBidders | INT | fix_417 | BIGINT |
| 418 | TradeType | CHAR | fix_418 | VARCHAR |
| 419 | BasisPxType | CHAR | fix_419 | VARCHAR |
| 420 | NoBidComponents | INT | fix_420 | BIGINT |
| 421 | Country | STRING | fix_421 | VARCHAR |
| 422 | TotNoStrikes | INT | fix_422 | BIGINT |
| 423 | PriceType | INT | fix_423 | BIGINT |
| 424 | DayOrderQty | QTY | fix_424 | DOUBLE |
| 425 | DayCumQty | QTY | fix_425 | DOUBLE |
| 426 | DayAvgPx | PRICE | fix_426 | DOUBLE |
| 427 | GTBookingInst | INT | fix_427 | BIGINT |
| 428 | NoStrikes | INT | fix_428 | BIGINT |
| 429 | ListStatusType | INT | fix_429 | BIGINT |
| 430 | NetGrossInd | INT | fix_430 | BIGINT |
| 431 | ListOrderStatus | INT | fix_431 | BIGINT |
| 432 | ExpireDate | LOCALMKTDATE | fix_432 | VARCHAR |
| 433 | ListExecInstType | CHAR | fix_433 | VARCHAR |
| 434 | CxlRejResponseTo | CHAR | fix_434 | VARCHAR |
| 435 | UnderlyingCouponRate | FLOAT | fix_435 | DOUBLE |
| 436 | UnderlyingContractMultiplier | FLOAT | fix_436 | DOUBLE |
| 437 | ContraTradeQty | QTY | fix_437 | DOUBLE |
| 438 | ContraTradeTime | UTCTIMESTAMP | fix_438 | VARCHAR |
| 439 | ClearingFirm | STRING | fix_439 | VARCHAR |
| 440 | ClearingAccount | STRING | fix_440 | VARCHAR |
| 441 | LiquidityNumSecurities | INT | fix_441 | BIGINT |
| 442 | MultiLegReportingType | CHAR | fix_442 | VARCHAR |
| 443 | StrikeTime | UTCTIMESTAMP | fix_443 | VARCHAR |
| 444 | ListStatusText | STRING | fix_444 | VARCHAR |
| 445 | EncodedListStatusTextLen | LENGTH | fix_445 | BIGINT |
| 446 | EncodedListStatusText | DATA | fix_446 | VARCHAR |

---

## 5. Repeating Groups and LENGTH/DATA Fields

- **Repeating groups are NOT exploded.** FIX repeating groups (e.g. 268
  NoMDEntries followed by N repetitions of 269/270/271...) repeat the same
  tag within one message. With one column per tag the FIRST occurrence wins;
  every dropped occurrence increments hdr_dupTagCount, so rows containing
  repeating groups are identifiable (hdr_dupTagCount > 0) even though only
  the first group entry is stored. The group count tag itself (NoXXX) is
  stored normally.
- **LENGTH/DATA pairs**: a DATA typed field (89 Signature, 91 SecureData,
  96 RawData, 213 XmlData, 349+ EncodedXXX, 446) may contain ARBITRARY
  bytes including SOH. The spec requires its byte length in the immediately
  preceding LENGTH typed field (93, 90, 95, 212, 348+, 445): the tokenizer
  remembers the last LENGTH value and consumes exactly that many bytes as
  the DATA value instead of scanning for SOH. A missing/implausible length
  falls back to the SOH scan. Non printable bytes in the stored value are
  replaced with `.` (parquet strings must be valid text).

---

## 6. Decoder Implementation Notes

1. **TCP protocol**: registers with .ipProto = IPV4_PROTO_TCP, receives
   reassembled stream segments. Each direction of a connection is a
   separate flow with its own framing state (FIXEndpoint_t: partial
   message accumulator). payload=NULL length=0 = stream reset (new SYN):
   discard the partial buffer.
2. **Framing** per section 1: accumulate, frame on 8=/9=, verify the 10=
   trailer position, resync on any inconsistency by scanning for the next
   "8=FIX". The accumulator is capped (FIX_ACCUM_MAX); overflow (only
   possible on garbage length prefixes) resets the stream state.
3. **Checksum is computed BEFORE tokenizing** (tokenizing overwrites the
   SOH delimiters with NUL terminators in the accumulator, which would
   corrupt the sum). Bad checksum still emits the row, flagged
   hdr_checksumValid = 0.
4. **Tokenizer**: tag = ASCII digits up to '='; value = bytes up to SOH
   (or the LENGTH-armed byte count for DATA fields). Malformed pair (no
   digits / no '=') = skip to the next SOH. Values are NUL terminated in
   place and non printable bytes (including embedded NUL) are replaced
   with '.' so every stored value is a valid string.
5. **One row per FIX message** - admin and application messages alike,
   including PossDup retransmits and messages with a BAD CHECKSUM (flagged,
   not dropped: on an order entry wire the malformed message still reached
   the counterparty's TCP socket).
6. **First occurrence wins** for duplicate tags (repeating groups, section
   5); hdr_dupTagCount counts the drops. Tags > 1024 are dropped and
   counted in hdr_overflowTagCount.
7. **The decoder never validates business content**: sequence gaps,
   session state, order lifecycle are parquet queries (fix_34, fix_35,
   fix_11/37/41 chains), not decoder state. The only per flow state is
   the framing accumulator.
8. **Cross protocol/venue joins**: FIX deployments differ; typical keys
   are fix_11 (ClOrdID), fix_37 (OrderID), fix_17 (ExecID), fix_55/48
   (Symbol/SecurityID).

---

## 7. Flat Parquet Schema

One row per FIX message, table `fix`, 1042 columns total: 15 shared capture
layer columns + 3 transport columns + 1024 tag columns. Generated into
fix42_schema.h by gen_tables.py - the full column list is the tag
dictionary (section 4).

```sql
CREATE TABLE fix (
    -- capture layer (shared across all protocol schemas, src/fCapture.h)
    "frame_ts"          UBIGINT,   -- pcap timestamp, ns since epoch
    -- ... frame_ipSrc/ipDst/portSrc/portDst/ipProto, frame_vlanOuter/Inner,
    -- frame_pbTS/pbFlags/pbDeviceID/pbPortID, frame_hostname,
    -- frame_pkt_block/pkt_offset (15 columns, see fCapture.h)

    -- transport layer (FIX framing metadata, not tag values)
    "hdr_checksumValid"    UTINYINT,  -- computed sum mod 256 == tag 10: 1 ok, 0 mismatch
    "hdr_dupTagCount"      USMALLINT, -- tag occurrences dropped by first-wins (repeating groups)
    "hdr_overflowTagCount" USMALLINT, -- tags > 1024 dropped from this message

    -- one column per FIX tag; typed from the dictionary (section 4)
    "fix_1"   VARCHAR,   -- Account
    "fix_6"   DOUBLE,    -- AvgPx
    "fix_8"   VARCHAR,   -- BeginString
    "fix_9"   BIGINT,    -- BodyLength
    "fix_34"  BIGINT,    -- MsgSeqNum
    "fix_35"  VARCHAR,   -- MsgType
    -- ... fix_2 .. fix_1024, one column per tag
);
```

Typical queries:

```sql
-- message type distribution per session
SELECT fix_49, fix_56, fix_35, count(*) FROM read_parquet('fix.parq')
GROUP BY ALL ORDER BY ALL;

-- sequence gap check per direction
SELECT fix_49, fix_34 - lag(fix_34) OVER (PARTITION BY fix_49 ORDER BY frame_ts) AS d
FROM read_parquet('fix.parq') QUALIFY d != 1;

-- order lifecycle by ClOrdID
SELECT frame_ts, fix_35, fix_39, fix_150, fix_44, fix_38, fix_14
FROM read_parquet('fix.parq') WHERE fix_11 = 'ORDER123' ORDER BY frame_ts;
```

---

## 8. TCP Addressing / Classification

FIX has NO well known endpoints: every counterparty pair negotiates its own
addresses and ports, so - unlike every other decoder in this project - the
flow classifier cannot recognize FIX from the 4-tuple. The decoder
therefore:

- registers with .noAutoDetect = true: it NEVER participates in -p auto
  autodetection (a catch-all classifier would steal every TCP flow from
  protocols with real endpoint patterns, e.g. jgate30_oe_ouch)
- must be selected explicitly: -p fix42 (or -p fix)
- then classifies EVERY TCP flow (classify always matches) and relies on
  the framing layer as the content filter: a flow that never yields a
  "8=FIX" framed message emits no rows (the resync scan discards the
  bytes, bounded by the accumulator tail)

To restrict a decode to one counterparty/session, filter the pcap upstream
or filter the parquet on frame_ipSrc/frame_portDst/fix_49/fix_56; for a
site with fixed FIX ports the classifier in fix42.c is the place to add a
port match.

---

## 9. Decoder Validation

### 9.1 Synthetic unit test - validate/ suite

gen_pcap.lua builds a synthetic TCP capture (handshake + FIX session) and
validate_synthetic.lua decodes it (-p fix42) and field-checks the parquet
output with duckdb. Coverage:

- Logon / Heartbeat / NewOrderSingle / ExecutionReport / OrderCancelRequest
  / Logout with hand computed checksums and known field values
- both directions of the connection (client and server flows)
- a FIX message split across TCP segments (partial frame accumulation)
- multiple FIX messages packed into one TCP segment
- an out of order TCP segment (tcpstream reassembly on FIX frames)
- a repeating group (first-wins + hdr_dupTagCount)
- a LENGTH/DATA pair with embedded SOH in the value (96 RawData)
- a custom tag in 447..1024 and a tag > 1024 (hdr_overflowTagCount)
- a corrupted checksum (row emitted, hdr_checksumValid = 0)
- mid stream capture start (resync onto the next 8=FIX boundary)
- negative: a non FIX TCP flow emits no rows
- negative: -p auto never claims the FIX flows (noAutoDetect, no output
  written)

Status: 21/21 PASS (make synthetic).

### 9.2 Real capture validation - PENDING

No FIX capture exists yet under data/protocol/fix42/. Candidate references
for cross validation: tshark's built in FIX dissector (-d tcp.port==X,fix
-T fields -E occurrence=a), or the counterparty's own FIX engine logs
(sequence numbers + ClOrdID join).
