//------------------------------------------------------------------------------
//
// opra_md_pillar6.c
//
// OPRA Pillar Binary v6 protocol decoder.
//
// Parquet schema creation for the flat OPRA output table. One row per decoded
// OPRA message (all categories including Control); the schema is the union of
// every column in the protocol. See opra_md_pillar6.md section 7 for the full
// specification.
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "fTypes.h"
#include "fParquet.h"
#include "parq.h"
#include "opra_md_pillar6.h"

#define OPRA6_TABLE_NAME	"opra"

// flat schema: union of every column in the OPRA Pillar v6 protocol
static const ParquetColumn_t s_schema[] =
{
	// capture layer (5-tuple + vlan + arista 7130 trailer), see fCapture.h
	CAPTURE_SCHEMA_COLUMNS
	// transport layer (every row)
	{ "hdr_lineNumber",                     PARQUET_TYPE_U16          },	// OPRA line from classifier (1-96, 220-225, 201-204)
	{ "hdr_feedStream",                     PARQUET_TYPE_STRING       },	// 'A' or 'B' multicast stream
	{ "hdr_retransmission",                 PARQUET_TYPE_STRING       },	// 'V' if retransmitted block, else NULL
	{ "hdr_sessionIndicator",               PARQUET_TYPE_U8           },	// raw byte: 0 RTH, 1-5 GTH day, 0x58 ('X') OPRA generated GTH
	{ "hdr_blockTimestampNS",               PARQUET_TYPE_U64          },	// block timestamp, ns since epoch
	{ "hdr_blockSeqNo",                     PARQUET_TYPE_U32          },	// block sequence number as transmitted
	{ "hdr_msgSeqNo",                       PARQUET_TYPE_U32          },	// blockSeqNo + index of message within block
	// message header (every row)
	{ "msg_participantId",                  PARQUET_TYPE_STRING       },	// exchange code
	{ "msg_category",                       PARQUET_TYPE_STRING       },	// a d f k q C H R Y
	{ "msg_type",                           PARQUET_TYPE_STRING       },	// type within category (space kept as ' ')
	{ "msg_indicator",                      PARQUET_TYPE_STRING       },	// BBO indicator for k/q, else NULL
	{ "msg_transactionId",                  PARQUET_TYPE_U32          },
	{ "msg_participantRefNo",               PARQUET_TYPE_U32          },
	// option series identity (a d f k q R)
	{ "msg_symbol",                         PARQUET_TYPE_STRING       },	// underlying symbol, space padding stripped
	{ "msg_expirationMonthCode",            PARQUET_TYPE_STRING       },	// raw A-X code
	{ "msg_putCall",                        PARQUET_TYPE_STRING       },	// derived: 'C' or 'P'
	{ "msg_expirationMonth",                PARQUET_TYPE_U8           },	// derived: 1-12
	{ "msg_expirationDay",                  PARQUET_TYPE_U8           },	// 1-31
	{ "msg_expirationYear",                 PARQUET_TYPE_U16          },	// derived: 2000 + raw
	{ "msg_strikePrice",                    PARQUET_TYPE_DECIMAL20_8  },
	// a: Equity and Index Last Sale
	{ "msg_volume",                         PARQUET_TYPE_U32          },	// a (trade size), f (daily volume)
	{ "msg_premiumPrice",                   PARQUET_TYPE_DECIMAL20_8  },	// trade price
	{ "msg_tradeIdentifier",                PARQUET_TYPE_U32          },	// future use, currently 0
	{ "msg_tradingSessionId",               PARQUET_TYPE_U8           },	// 0 regular, 1 extended
	// d: Open Interest (also f)
	{ "msg_openInterestVolume",             PARQUET_TYPE_U32          },
	// f: Equity and Index End of Day Summary
	{ "msg_openPrice",                      PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_highPrice",                      PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_lowPrice",                       PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_lastPrice",                      PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_netChange",                      PARQUET_TYPE_DECIMAL20_8  },	// signed
	{ "msg_underlyingPrice",                PARQUET_TYPE_DECIMAL20_8  },
	// k/q: Equity and Index Quote (bidPrice/offerPrice also f)
	{ "msg_bidPrice",                       PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_bidSize",                        PARQUET_TYPE_U32          },
	{ "msg_offerPrice",                     PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_offerSize",                      PARQUET_TYPE_U32          },
	// k/q BBO appendages (NULL when no appendage)
	{ "msg_bestBidParticipantId",           PARQUET_TYPE_STRING       },
	{ "msg_bestBidPrice",                   PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_bestBidSize",                    PARQUET_TYPE_U32          },
	{ "msg_bestOfferParticipantId",         PARQUET_TYPE_STRING       },
	{ "msg_bestOfferPrice",                 PARQUET_TYPE_DECIMAL20_8  },
	{ "msg_bestOfferSize",                  PARQUET_TYPE_U32          },
	// C: Administrative
	{ "msg_adminText",                      PARQUET_TYPE_STRING       },	// raw message data, printable ASCII
	// R: Series Mapping
	{ "msg_multicastLineNumber",            PARQUET_TYPE_U16          },	// assigned output line 1-96
	// Y: Underlying Value
	{ "msg_indexValue",                     PARQUET_TYPE_DECIMAL20_8  },	// type ' '
	{ "msg_bidIndexValue",                  PARQUET_TYPE_DECIMAL20_8  },	// type 'I'
	{ "msg_offerIndexValue",                PARQUET_TYPE_DECIMAL20_8  },	// type 'I'
};

//------------------------------------------------------------------------------
// Protocol_OPRA6PacketClassify: OPRA multicast addressing is fully patterned
// (see opra_md_pillar6.md section 8, NMS network spec v1.59). The line number,
// stream (A/B) and feed type (production/retransmission/playback) are computed
// from the group/port arithmetic; group and port must agree.
//
//   Regular session line N (1-96), line 220-225 mapped to group octet 105-110:
//     production      A 224.0.204.N   :45000+N    B 224.0.206.N   :45000+N
//     retransmission  A 224.0.204.127+N :46000+N  B 224.0.206.127+N :46000+N
//                       (line 220-225 = group octet 232-237, port 46232-46237)
//     playback test   A 224.0.205.N   :47000+N    B 224.0.207.N   :47000+N
//
//   GTH line 201-204 (M = line - 200):
//     production      A 224.0.200.M    :48000+M   B 224.0.200.127+M :48000+M
//     retransmission  A 224.0.200.15+M :49000+M   B 224.0.200.143+M :49000+M
//     playback test   A 224.0.200.31+M :50000+M   B 224.0.200.159+M :50000+M
//------------------------------------------------------------------------------

#define IP4(a,b,c,d)	(((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | (u32)(d))

// regular session group octet -> line number. octets 1-96 are lines 1-96,
// octets 105-110 are lines 220-225 (105 offset applies to production/playback,
// 232-237 to retransmission). returns 0 if the octet is not an OPRA line
static u16 opra6RegularLine(u32 octet)
{
	if ((octet >= 1) && (octet <= 96))
	{
		return (u16)octet;
	}
	if ((octet >= 105) && (octet <= 110))
	{
		return (u16)(220 + octet - 105);
	}
	return 0;
}

bool Protocol_OPRA6PacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpointArg)
{
	(void)ipSrc;
	(void)portSrc;

	OPRA6Endpoint_t* endpoint = (OPRA6Endpoint_t*)endpointArg;

	u32 subnet = ipDst & 0xffffff00;
	u32 octet  = ipDst & 0xff;

	// regular session: 224.0.204.x (A) / 224.0.206.x (B) production +
	// retransmission, 224.0.205.x (A) / 224.0.207.x (B) playback test
	if ((subnet == IP4(224,0,204,0)) || (subnet == IP4(224,0,206,0)))
	{
		char stream = (subnet == IP4(224,0,204,0)) ? 'A' : 'B';

		if (octet <= 110)
		{
			// production: port 45001-45096 (lines) / 45105-45110 (220-225)
			u16 line = opra6RegularLine(octet);
			if ((line != 0) && (portDst == 45000 + octet))
			{
				endpoint->lineNumber = line;
				endpoint->feedStream = stream;
				endpoint->feedType   = 'P';
				return true;
			}
		}
		else
		{
			// retransmission: group octet 128-223 = lines 1-96 port 46001-46096,
			// group octet 232-237 = lines 220-225 port 46232-46237
			if ((octet >= 128) && (octet <= 223) && (portDst == 46000 + (octet - 127)))
			{
				endpoint->lineNumber = (u16)(octet - 127);
				endpoint->feedStream = stream;
				endpoint->feedType   = 'R';
				return true;
			}
			if ((octet >= 232) && (octet <= 237) && (portDst == 46000 + octet))
			{
				endpoint->lineNumber = (u16)(220 + octet - 232);
				endpoint->feedStream = stream;
				endpoint->feedType   = 'R';
				return true;
			}
		}
		return false;
	}

	if ((subnet == IP4(224,0,205,0)) || (subnet == IP4(224,0,207,0)))
	{
		u16 line = opra6RegularLine(octet);
		if ((line != 0) && (portDst == 47000 + octet))
		{
			endpoint->lineNumber = line;
			endpoint->feedStream = (subnet == IP4(224,0,205,0)) ? 'A' : 'B';
			endpoint->feedType   = 'T';
			return true;
		}
		return false;
	}

	// GTH lines 201-204 on 224.0.200.x; the same subnet also carries CTS/CQS
	// groups so both the exact group octet AND the OPRA GTH port must match
	if (subnet == IP4(224,0,200,0))
	{
		static const struct
		{
			u32		octetBase;	// group octet of GTH line 201
			u16		portBase;	// port of GTH line 201
			char	stream;
			char	feedType;
		} gthSet[] =
		{
			{   1, 48001, 'A', 'P' },
			{ 128, 48001, 'B', 'P' },
			{  16, 49001, 'A', 'R' },
			{ 144, 49001, 'B', 'R' },
			{  32, 50001, 'A', 'T' },
			{ 160, 50001, 'B', 'T' },
		};

		for (u32 i = 0; i < sizeof(gthSet) / sizeof(gthSet[0]); i++)
		{
			if ((octet >= gthSet[i].octetBase) && (octet <= gthSet[i].octetBase + 3) && (portDst == gthSet[i].portBase + (octet - gthSet[i].octetBase)))
			{
				endpoint->lineNumber = (u16)(201 + octet - gthSet[i].octetBase);
				endpoint->feedStream = gthSet[i].stream;
				endpoint->feedType   = gthSet[i].feedType;
				return true;
			}
		}
		return false;
	}

	return false;
}

//------------------------------------------------------------------------------
// big endian field readers
//------------------------------------------------------------------------------
static INLINE u16 readBE16(const u8* p)
{
	return ((u16)p[0] << 8) | (u16)p[1];
}

static INLINE u32 readBE32(const u8* p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static INLINE u64 readBE64(const u8* p)
{
	return ((u64)readBE32(p) << 32) | (u64)readBE32(p + 4);
}

//------------------------------------------------------------------------------
// denominator codes: prices and index values are integers with an implied
// decimal point given by a 1 byte alphabetic code (opra_md_pillar6.md 2.4)
//------------------------------------------------------------------------------
static double denomScale(char code)
{
	switch (code)
	{
	case 'A':
		return 1e1;
	case 'B':
		return 1e2;
	case 'C':
		return 1e3;
	case 'D':
		return 1e4;
	case 'E':
		return 1e5;
	case 'F':
		return 1e6;
	case 'G':
		return 1e7;
	case 'H':
		return 1e8;
	case 'I':
		return 1.0;
	default:
		// unknown code: no scaling
		return 1.0;
	}
}

// 4 byte signed price scaled by denominator code
static INLINE double priceRead4(const u8* p, char denom)
{
	return (double)(s32)readBE32(p) / denomScale(denom);
}

// 8 byte signed price scaled by denominator code (underlying price)
static INLINE double priceRead8(const u8* p, char denom)
{
	return (double)(s64)readBE64(p) / denomScale(denom);
}

// alpha fields: left justified, right padded with spaces. trailing spaces
// are stripped; an all-space field becomes an empty string (stored as NULL)
static void alphaCopy(char* dst, const u8* src, u32 n)
{
	u32 len = n;
	while ((len > 0) && (src[len - 1] == ' '))
	{
		len--;
	}
	memcpy(dst, src, len);
	dst[len] = 0;
}

// single raw character field, kept even when it is a space
static INLINE void charCopy(char* dst, u8 c)
{
	dst[0] = (char)c;
	dst[1] = 0;
}

//------------------------------------------------------------------------------
// decoded row: union of every column in the flat schema. varchar fields use
// an empty string to mean NULL; numeric fields use the fieldMask bit
//------------------------------------------------------------------------------

// bit positions in OPRA6Row_t.fieldMask for the optional numeric columns
enum
{
	ROW_EXPIRATIONMONTH = 0,
	ROW_EXPIRATIONDAY,
	ROW_EXPIRATIONYEAR,
	ROW_STRIKEPRICE,
	ROW_VOLUME,
	ROW_PREMIUMPRICE,
	ROW_TRADEIDENTIFIER,
	ROW_TRADINGSESSIONID,
	ROW_OPENINTERESTVOLUME,
	ROW_OPENPRICE,
	ROW_HIGHPRICE,
	ROW_LOWPRICE,
	ROW_LASTPRICE,
	ROW_NETCHANGE,
	ROW_UNDERLYINGPRICE,
	ROW_BIDPRICE,
	ROW_BIDSIZE,
	ROW_OFFERPRICE,
	ROW_OFFERSIZE,
	ROW_BESTBIDPRICE,
	ROW_BESTBIDSIZE,
	ROW_BESTOFFERPRICE,
	ROW_BESTOFFERSIZE,
	ROW_MULTICASTLINENUMBER,
	ROW_INDEXVALUE,
	ROW_BIDINDEXVALUE,
	ROW_OFFERINDEXVALUE,
};

#define ROW_SET(r, f)	((r)->fieldMask |= (1ULL << (f)))
#define ROW_HAS(r, f)	(((r)->fieldMask >> (f)) & 1ULL)

typedef struct
{
	// transport: always populated
	u16		lineNumber;
	char	feedStream[2];
	char	retransmission[2];			// empty == NULL (original transmission)
	u8		sessionIndicator;
	u64		blockTimestampNS;
	u32		blockSeqNo;
	u32		msgSeqNo;

	// message header: always populated (msgIndicator only for k/q)
	char	participantId[2];
	char	msgCategory[2];
	char	msgType[2];
	char	msgIndicator[2];
	u32		transactionId;
	u32		participantRefNo;

	u64		fieldMask;					// optional numeric column validity bits

	// varchar columns (empty string == NULL)
	char	symbol[8];
	char	expirationMonthCode[2];
	char	putCall[2];
	char	bestBidParticipantId[2];
	char	bestOfferParticipantId[2];
	char	adminText[204];				// max 200 data bytes + terminator

	// numeric columns, valid when the matching fieldMask bit is set
	u8		expirationMonth;
	u8		expirationDay;
	u16		expirationYear;
	double	strikePrice;
	u32		volume;
	double	premiumPrice;
	u32		tradeIdentifier;
	u8		tradingSessionId;
	u32		openInterestVolume;
	double	openPrice;
	double	highPrice;
	double	lowPrice;
	double	lastPrice;
	double	netChange;
	double	underlyingPrice;
	double	bidPrice;
	u32		bidSize;
	double	offerPrice;
	u32		offerSize;
	double	bestBidPrice;
	u32		bestBidSize;
	double	bestOfferPrice;
	u32		bestOfferSize;
	u16		multicastLineNumber;
	double	indexValue;
	double	bidIndexValue;
	double	offerIndexValue;

} OPRA6Row_t;

//------------------------------------------------------------------------------
// append helpers: NULL for empty strings / unset numeric fields
//------------------------------------------------------------------------------
static void appendU8Opt(Parquet_t* pq, OPRA6Row_t* r, u32 bit, u8 v)
{
	if (ROW_HAS(r, bit))
	{
		parquetAppendU8(pq, v);
	}
	else
	{
		parquetAppendNull(pq);
	}
}

static void appendU16Opt(Parquet_t* pq, OPRA6Row_t* r, u32 bit, u16 v)
{
	if (ROW_HAS(r, bit))
	{
		parquetAppendU16(pq, v);
	}
	else
	{
		parquetAppendNull(pq);
	}
}

static void appendU32Opt(Parquet_t* pq, OPRA6Row_t* r, u32 bit, u32 v)
{
	if (ROW_HAS(r, bit))
	{
		parquetAppendU32(pq, v);
	}
	else
	{
		parquetAppendNull(pq);
	}
}

static void appendDblOpt(Parquet_t* pq, OPRA6Row_t* r, u32 bit, double v)
{
	if (ROW_HAS(r, bit))
	{
		parquetAppendDouble(pq, v);
	}
	else
	{
		parquetAppendNull(pq);
	}
}

//------------------------------------------------------------------------------
// opra6RowAppend: write one decoded row in exact schema column order
//------------------------------------------------------------------------------
static bool opra6RowAppend(Parquet_t* pq, const PacketInfo_t* pkt, OPRA6Row_t* r)
{
	parquetRowBegin(pq);

	// capture layer (5-tuple + vlan + arista 7130 trailer)
	packetInfoAppend(pq, pkt);

	// transport layer
	parquetAppendU16(pq, r->lineNumber);
	parquetAppendStr(pq, r->feedStream);
	parquetAppendStr(pq, r->retransmission);
	parquetAppendU8(pq, r->sessionIndicator);
	parquetAppendU64(pq, r->blockTimestampNS);
	parquetAppendU32(pq, r->blockSeqNo);
	parquetAppendU32(pq, r->msgSeqNo);

	// message header
	parquetAppendStr(pq, r->participantId);
	parquetAppendStr(pq, r->msgCategory);
	parquetAppendStr(pq, r->msgType);
	parquetAppendStr(pq, r->msgIndicator);
	parquetAppendU32(pq, r->transactionId);
	parquetAppendU32(pq, r->participantRefNo);

	// option series identity
	parquetAppendStr(pq, r->symbol);
	parquetAppendStr(pq, r->expirationMonthCode);
	parquetAppendStr(pq, r->putCall);
	appendU8Opt(pq, r, ROW_EXPIRATIONMONTH, r->expirationMonth);
	appendU8Opt(pq, r, ROW_EXPIRATIONDAY, r->expirationDay);
	appendU16Opt(pq, r, ROW_EXPIRATIONYEAR, r->expirationYear);
	appendDblOpt(pq, r, ROW_STRIKEPRICE, r->strikePrice);

	// a: Equity and Index Last Sale
	appendU32Opt(pq, r, ROW_VOLUME, r->volume);
	appendDblOpt(pq, r, ROW_PREMIUMPRICE, r->premiumPrice);
	appendU32Opt(pq, r, ROW_TRADEIDENTIFIER, r->tradeIdentifier);
	appendU8Opt(pq, r, ROW_TRADINGSESSIONID, r->tradingSessionId);

	// d: Open Interest
	appendU32Opt(pq, r, ROW_OPENINTERESTVOLUME, r->openInterestVolume);

	// f: Equity and Index End of Day Summary
	appendDblOpt(pq, r, ROW_OPENPRICE, r->openPrice);
	appendDblOpt(pq, r, ROW_HIGHPRICE, r->highPrice);
	appendDblOpt(pq, r, ROW_LOWPRICE, r->lowPrice);
	appendDblOpt(pq, r, ROW_LASTPRICE, r->lastPrice);
	appendDblOpt(pq, r, ROW_NETCHANGE, r->netChange);
	appendDblOpt(pq, r, ROW_UNDERLYINGPRICE, r->underlyingPrice);

	// k/q: Equity and Index Quote
	appendDblOpt(pq, r, ROW_BIDPRICE, r->bidPrice);
	appendU32Opt(pq, r, ROW_BIDSIZE, r->bidSize);
	appendDblOpt(pq, r, ROW_OFFERPRICE, r->offerPrice);
	appendU32Opt(pq, r, ROW_OFFERSIZE, r->offerSize);

	// k/q BBO appendages
	parquetAppendStr(pq, r->bestBidParticipantId);
	appendDblOpt(pq, r, ROW_BESTBIDPRICE, r->bestBidPrice);
	appendU32Opt(pq, r, ROW_BESTBIDSIZE, r->bestBidSize);
	parquetAppendStr(pq, r->bestOfferParticipantId);
	appendDblOpt(pq, r, ROW_BESTOFFERPRICE, r->bestOfferPrice);
	appendU32Opt(pq, r, ROW_BESTOFFERSIZE, r->bestOfferSize);

	// C: Administrative
	parquetAppendStr(pq, r->adminText);

	// R: Series Mapping
	appendU16Opt(pq, r, ROW_MULTICASTLINENUMBER, r->multicastLineNumber);

	// Y: Underlying Value
	appendDblOpt(pq, r, ROW_INDEXVALUE, r->indexValue);
	appendDblOpt(pq, r, ROW_BIDINDEXVALUE, r->bidIndexValue);
	appendDblOpt(pq, r, ROW_OFFERINDEXVALUE, r->offerIndexValue);

	return parquetRowEnd(pq);
}

//------------------------------------------------------------------------------
// expirationDecode: 3 byte expiration block (opra_md_pillar6.md 2.5).
// month code A-L = Jan-Dec call, M-X = Jan-Dec put
//------------------------------------------------------------------------------
static void expirationDecode(OPRA6Row_t* r, const u8* p)
{
	char monthCode = (char)p[0];
	charCopy(r->expirationMonthCode, p[0]);

	if ((monthCode >= 'A') && (monthCode <= 'L'))
	{
		r->putCall[0] = 'C';
		r->putCall[1] = 0;
		r->expirationMonth = (u8)(monthCode - 'A' + 1);
		ROW_SET(r, ROW_EXPIRATIONMONTH);
	}
	else if ((monthCode >= 'M') && (monthCode <= 'X'))
	{
		r->putCall[0] = 'P';
		r->putCall[1] = 0;
		r->expirationMonth = (u8)(monthCode - 'M' + 1);
		ROW_SET(r, ROW_EXPIRATIONMONTH);
	}

	r->expirationDay = p[1];
	r->expirationYear = (u16)(2000 + p[2]);
	ROW_SET(r, ROW_EXPIRATIONDAY);
	ROW_SET(r, ROW_EXPIRATIONYEAR);
}

//------------------------------------------------------------------------------
// bboAppendageLen: appendage bytes following a k/q quote body, derived from the
// BBO Indicator in the message header (opra_md_pillar6.md 5.3)
//------------------------------------------------------------------------------
static u32 bboAppendageLen(u8 indicator)
{
	switch (indicator)
	{
	case 'C':
	case 'G':
	case 'K':	// single Best Offer appendage
	case 'M':
	case 'N':
	case 'P':	// single Best Bid appendage
		return 10;
	case 'O':	// double appendage: Best Bid then Best Offer
		return 20;
	default:
		return 0;
	}
}

// decode one 10 byte appendage: participant(1) denominator(1) price(4) size(4)
static void bboAppendageDecode(OPRA6Row_t* r, const u8* p, bool isBid)
{
	if (isBid)
	{
		charCopy(r->bestBidParticipantId, p[0]);
		r->bestBidPrice = priceRead4(p + 2, (char)p[1]);
		r->bestBidSize = readBE32(p + 6);
		ROW_SET(r, ROW_BESTBIDPRICE);
		ROW_SET(r, ROW_BESTBIDSIZE);
	}
	else
	{
		charCopy(r->bestOfferParticipantId, p[0]);
		r->bestOfferPrice = priceRead4(p + 2, (char)p[1]);
		r->bestOfferSize = readBE32(p + 6);
		ROW_SET(r, ROW_BESTOFFERPRICE);
		ROW_SET(r, ROW_BESTOFFERSIZE);
	}
}

//------------------------------------------------------------------------------
// opra6MsgDecode: decode a single OPRA message and append it as one row.
// msg points at the 12 byte message header, avail is the bytes remaining in
// the block. returns the total message length consumed, or 0 when the message
// is unknown / truncated (the caller must abandon the block: without a per
// message length field the remaining messages cannot be located)
//------------------------------------------------------------------------------
static u32 opra6MsgDecode(Parquet_t* pq, const PacketInfo_t* pkt, OPRA6Row_t* rowTemplate, const u8* msg, u32 avail)
{
	if (avail < 12)
	{
		return 0;
	}

	OPRA6Row_t row = *rowTemplate;

	u8 category  = msg[1];
	u8 indicator = msg[3];

	charCopy(row.participantId, msg[0]);
	charCopy(row.msgCategory, category);
	charCopy(row.msgType, msg[2]);
	row.transactionId = readBE32(msg + 4);
	row.participantRefNo = readBE32(msg + 8);

	u32 msgLen = 0;
	switch (category)
	{
	case 'a':	// Equity and Index Last Sale (43)
	{
		msgLen = 43;
		if (avail < msgLen) return 0;
		alphaCopy(row.symbol, msg + 12, 5);
		expirationDecode(&row, msg + 18);
		row.strikePrice = priceRead4(msg + 22, (char)msg[21]);
		ROW_SET(&row, ROW_STRIKEPRICE);
		row.volume = readBE32(msg + 26);
		ROW_SET(&row, ROW_VOLUME);
		row.premiumPrice = priceRead4(msg + 31, (char)msg[30]);
		ROW_SET(&row, ROW_PREMIUMPRICE);
		row.tradeIdentifier = readBE32(msg + 35);
		ROW_SET(&row, ROW_TRADEIDENTIFIER);
		row.tradingSessionId = msg[39];
		ROW_SET(&row, ROW_TRADINGSESSIONID);
	}
	break;

	case 'd':	// Open Interest (30)
	{
		msgLen = 30;
		if (avail < msgLen) return 0;
		alphaCopy(row.symbol, msg + 12, 5);
		expirationDecode(&row, msg + 18);
		row.strikePrice = priceRead4(msg + 22, (char)msg[21]);
		ROW_SET(&row, ROW_STRIKEPRICE);
		row.openInterestVolume = readBE32(msg + 26);
		ROW_SET(&row, ROW_OPENINTERESTVOLUME);
	}
	break;

	case 'f':	// Equity and Index End of Day Summary (72)
	{
		msgLen = 72;
		if (avail < msgLen) return 0;
		alphaCopy(row.symbol, msg + 12, 5);
		expirationDecode(&row, msg + 18);
		row.strikePrice = priceRead4(msg + 22, (char)msg[21]);
		ROW_SET(&row, ROW_STRIKEPRICE);
		row.volume = readBE32(msg + 26);
		ROW_SET(&row, ROW_VOLUME);
		row.openInterestVolume = readBE32(msg + 30);
		ROW_SET(&row, ROW_OPENINTERESTVOLUME);

		char premDenom = (char)msg[34];
		row.openPrice = priceRead4(msg + 35, premDenom);
		row.highPrice = priceRead4(msg + 39, premDenom);
		row.lowPrice  = priceRead4(msg + 43, premDenom);
		row.lastPrice = priceRead4(msg + 47, premDenom);
		row.netChange = priceRead4(msg + 51, premDenom);
		ROW_SET(&row, ROW_OPENPRICE);
		ROW_SET(&row, ROW_HIGHPRICE);
		ROW_SET(&row, ROW_LOWPRICE);
		ROW_SET(&row, ROW_LASTPRICE);
		ROW_SET(&row, ROW_NETCHANGE);

		row.underlyingPrice = priceRead8(msg + 56, (char)msg[55]);
		ROW_SET(&row, ROW_UNDERLYINGPRICE);

		row.bidPrice = priceRead4(msg + 64, premDenom);
		row.offerPrice = priceRead4(msg + 68, premDenom);
		ROW_SET(&row, ROW_BIDPRICE);
		ROW_SET(&row, ROW_OFFERPRICE);
	}
	break;

	case 'k':	// Long Equity and Index Quote (43 + appendage)
	{
		u32 appLen = bboAppendageLen(indicator);
		msgLen = 43 + appLen;
		if (avail < msgLen) return 0;
		charCopy(row.msgIndicator, indicator);
		alphaCopy(row.symbol, msg + 12, 5);
		expirationDecode(&row, msg + 18);
		row.strikePrice = priceRead4(msg + 22, (char)msg[21]);
		ROW_SET(&row, ROW_STRIKEPRICE);

		char premDenom = (char)msg[26];
		row.bidPrice = priceRead4(msg + 27, premDenom);
		row.bidSize = readBE32(msg + 31);
		row.offerPrice = priceRead4(msg + 35, premDenom);
		row.offerSize = readBE32(msg + 39);
		ROW_SET(&row, ROW_BIDPRICE);
		ROW_SET(&row, ROW_BIDSIZE);
		ROW_SET(&row, ROW_OFFERPRICE);
		ROW_SET(&row, ROW_OFFERSIZE);

		if (appLen == 20)
		{
			bboAppendageDecode(&row, msg + 43, true);
			bboAppendageDecode(&row, msg + 53, false);
		}
		else if (appLen == 10)
		{
			bool isBid = (indicator == 'M') || (indicator == 'N') || (indicator == 'P');
			bboAppendageDecode(&row, msg + 43, isBid);
		}
	}
	break;

	case 'q':	// Short Equity and Index Quote (29 + appendage)
	{
		u32 appLen = bboAppendageLen(indicator);
		msgLen = 29 + appLen;
		if (avail < msgLen) return 0;
		charCopy(row.msgIndicator, indicator);
		alphaCopy(row.symbol, msg + 12, 4);
		expirationDecode(&row, msg + 16);

		// implied denominators: strike 'A' (divide by 10), premium 'B' (divide by 100)
		row.strikePrice = readBE16(msg + 19) / 1e1;
		ROW_SET(&row, ROW_STRIKEPRICE);
		row.bidPrice = readBE16(msg + 21) / 1e2;
		row.bidSize = readBE16(msg + 23);
		row.offerPrice = readBE16(msg + 25) / 1e2;
		row.offerSize = readBE16(msg + 27);
		ROW_SET(&row, ROW_BIDPRICE);
		ROW_SET(&row, ROW_BIDSIZE);
		ROW_SET(&row, ROW_OFFERPRICE);
		ROW_SET(&row, ROW_OFFERSIZE);

		if (appLen == 20)
		{
			bboAppendageDecode(&row, msg + 29, true);
			bboAppendageDecode(&row, msg + 39, false);
		}
		else if (appLen == 10)
		{
			bool isBid = (indicator == 'M') || (indicator == 'N') || (indicator == 'P');
			bboAppendageDecode(&row, msg + 29, isBid);
		}
	}
	break;

	case 'C':	// Administrative (14 + variable text)
	{
		if (avail < 14) return 0;
		u32 dataLen = readBE16(msg + 12);
		msgLen = 14 + dataLen;
		if ((dataLen >= sizeof(row.adminText)) || (avail < msgLen)) return 0;
		memcpy(row.adminText, msg + 14, dataLen);
		row.adminText[dataLen] = 0;
	}
	break;

	case 'H':	// Control (12, message header only)
	{
		msgLen = 12;
	}
	break;

	case 'R':	// Series Mapping Message (155); no reserved byte after symbol
	{
		msgLen = 155;
		if (avail < msgLen) return 0;
		alphaCopy(row.symbol, msg + 12, 5);
		expirationDecode(&row, msg + 17);
		row.strikePrice = priceRead4(msg + 21, (char)msg[20]);
		ROW_SET(&row, ROW_STRIKEPRICE);
		row.multicastLineNumber = readBE16(msg + 25);
		ROW_SET(&row, ROW_MULTICASTLINENUMBER);
	}
	break;

	case 'Y':	// Underlying Value (27)
	{
		msgLen = 27;
		if (avail < msgLen) return 0;
		alphaCopy(row.symbol, msg + 12, 5);

		char indexDenom = (char)msg[18];
		if (msg[2] == 'I')
		{
			// Index based on Bid and Offer
			row.bidIndexValue = priceRead4(msg + 19, indexDenom);
			row.offerIndexValue = priceRead4(msg + 23, indexDenom);
			ROW_SET(&row, ROW_BIDINDEXVALUE);
			ROW_SET(&row, ROW_OFFERINDEXVALUE);
		}
		else
		{
			// Index based on Last Sale
			row.indexValue = priceRead4(msg + 19, indexDenom);
			ROW_SET(&row, ROW_INDEXVALUE);
		}
	}
	break;

	default:
		// unknown category: length cannot be determined
		return 0;
	}

	if (!opra6RowAppend(pq, pkt, &row))
	{
		return 0;
	}
	return msgLen;
}

//------------------------------------------------------------------------------
// Protocol_OPRA6Decode: decode one OPRA transmission block (UDP payload) and
// append every contained message to the parquet table. returns the number of
// messages decoded
//------------------------------------------------------------------------------
u32 Protocol_OPRA6Decode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpointArg, const u8* payload, u32 payloadLen)
{
	const OPRA6Endpoint_t* endpoint = (const OPRA6Endpoint_t*)endpointArg;

	// block header: version(1) size(2) feed(1) retrans(1) session(1) seq(4)
	//               count(1) timestamp(8) checksum(2)
	if (payloadLen < 21)
	{
		return 0;
	}
	if ((payload[0] != 6) || (payload[3] != 'O'))
	{
		return 0;
	}

	u32 blockSize = readBE16(payload + 1);
	if (blockSize > payloadLen)
	{
		blockSize = payloadLen;
	}

	// row template: transport layer fields shared by every message in the block
	OPRA6Row_t rowTemplate;
	memset(&rowTemplate, 0, sizeof(rowTemplate));

	rowTemplate.lineNumber = endpoint->lineNumber;
	rowTemplate.feedStream[0] = endpoint->feedStream;
	rowTemplate.feedStream[1] = 0;
	if (payload[4] == 'V')
	{
		rowTemplate.retransmission[0] = 'V';
		rowTemplate.retransmission[1] = 0;
	}
	rowTemplate.sessionIndicator = payload[5];
	rowTemplate.blockSeqNo = readBE32(payload + 6);
	rowTemplate.blockTimestampNS = (u64)readBE32(payload + 11) * k1E9 + (u64)readBE32(payload + 15);

	u32 msgCount = payload[10];

	const u8* ptr = payload + 21;
	const u8* end = payload + blockSize;

	u32 decoded = 0;
	for (u32 i = 0; i < msgCount; i++)
	{
		// messages after the first are implicitly numbered sequentially
		rowTemplate.msgSeqNo = rowTemplate.blockSeqNo + i;

		u32 msgLen = opra6MsgDecode(pq, pkt, &rowTemplate, ptr, (u32)(end - ptr));
		if (msgLen == 0)
		{
			// unknown category or truncation: the block cannot be walked further
			break;
		}
		decoded++;
		ptr += msgLen;
	}

	return decoded;
}

//------------------------------------------------------------------------------
// Protocol_OPRA6SchemaCreate: create the OPRA table and appender on the context
//------------------------------------------------------------------------------
bool Protocol_OPRA6SchemaCreate(Parquet_t* pq)
{
	return parquetSchemaCreate(pq, OPRA6_TABLE_NAME, s_schema, sizeof(s_schema) / sizeof(s_schema[0]));
}

//------------------------------------------------------------------------------
// protocol registration: self registers at program start (see fProtocol.h),
// main.c and the Makefile carry no per protocol knowledge
//------------------------------------------------------------------------------
static Protocol_t s_protocolDesc =
{
	.name         = "opra_md_pillar6",
	.shortName    = "opra",
	.statsName    = "OPRA6",
	.description  = "OPRA Pillar Binary v6",
	.ipProto      = IPV4_PROTO_UDP,
	.endpointSize = sizeof(OPRA6Endpoint_t),
	.schemaCreate = Protocol_OPRA6SchemaCreate,
	.classify     = Protocol_OPRA6PacketClassify,
	.decode       = Protocol_OPRA6Decode,
};

static void __attribute__((constructor)) opra6Register(void)
{
	Protocol_Register(&s_protocolDesc);
}
