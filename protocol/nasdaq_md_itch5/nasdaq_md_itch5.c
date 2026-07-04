//------------------------------------------------------------------------------
//
// nasdaq_md_itch5.c
//
// Nasdaq TotalView-ITCH 5.0 protocol decoder.
//
// Parquet schema creation for the flat ITCH 5.0 output table. One row per
// decoded ITCH message; the schema is the union of every column in the
// protocol. See nasdaq_md_itch5.md section 7 for the full specification.
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "fTypes.h"
#include "fParquet.h"
#include "nasdaq_md_itch5.h"

#define ITCH5_TABLE_NAME	"itch"

// flat schema: union of every column in the ITCH 5.0 protocol
static const char* s_schemaSQL =
	"CREATE TABLE " ITCH5_TABLE_NAME " ("
	// capture / transport layer
	"    pcapTS                       UBIGINT,"		// pcap timestamp, ns since epoch
	"    moldSession                  VARCHAR,"		// MoldUDP64 session (10 alpha)
	"    moldSeqNo                    UBIGINT,"		// MoldUDP64 sequence number of this message
	"    msgType                      VARCHAR,"		// ITCH message type (1 alpha)
	// common ITCH header
	"    stockLocate                  USMALLINT,"
	"    trackingNumber               USMALLINT,"
	"    timestampNS                  UBIGINT,"		// ns since midnight ET (48 bit)
	// S: System Event
	"    eventCode                    VARCHAR,"
	// R: Stock Directory
	"    stock                        VARCHAR,"		// 8 alpha, space padding stripped
	"    marketCategory               VARCHAR,"
	"    financialStatusIndicator     VARCHAR,"
	"    roundLotSize                 UINTEGER,"
	"    roundLotsOnly                VARCHAR,"
	"    issueClassification          VARCHAR,"
	"    issueSubType                 VARCHAR,"
	"    authenticity                 VARCHAR,"
	"    shortSaleThresholdIndicator  VARCHAR,"
	"    ipoFlag                      VARCHAR,"
	"    luldReferencePriceTier       VARCHAR,"
	"    etpFlag                      VARCHAR,"
	"    etpLeverageFactor            UINTEGER,"
	"    inverseIndicator             VARCHAR,"
	// H: Stock Trading Action
	"    tradingState                 VARCHAR,"
	"    tradingActionReason          VARCHAR,"
	// Y: Reg SHO Restriction
	"    regSHOAction                 VARCHAR,"
	// L: Market Participant Position
	"    mpid                         VARCHAR,"
	"    primaryMarketMaker           VARCHAR,"
	"    marketMakerMode              VARCHAR,"
	"    marketParticipantState       VARCHAR,"
	// V/W: Market Wide Circuit Breaker
	"    mwcbLevel1                   DECIMAL(20,8),"
	"    mwcbLevel2                   DECIMAL(20,8),"
	"    mwcbLevel3                   DECIMAL(20,8),"
	"    mwcbBreachedLevel            VARCHAR,"
	// K: IPO Quoting Period Update
	"    ipoQuotationReleaseTime      UINTEGER,"		// seconds since midnight
	"    ipoQuotationReleaseQualifier VARCHAR,"
	"    ipoPrice                     DECIMAL(16,4),"
	// J: LULD Auction Collar
	"    auctionCollarReferencePrice  DECIMAL(16,4),"
	"    upperAuctionCollarPrice      DECIMAL(16,4),"
	"    lowerAuctionCollarPrice      DECIMAL(16,4),"
	"    auctionCollarExtension       UINTEGER,"
	// h: Operational Halt
	"    marketCode                   VARCHAR,"
	"    operationalHaltAction        VARCHAR,"
	// A/F/E/C/X/D/U/P: order book messages
	"    orderReferenceNumber         UBIGINT,"		// A F E C X D P
	"    originalOrderReferenceNumber UBIGINT,"		// U
	"    newOrderReferenceNumber      UBIGINT,"		// U
	"    buySellIndicator             VARCHAR,"		// A F P
	"    shares                       UBIGINT,"		// A F U P (4 byte), Q (8 byte)
	"    price                        DECIMAL(16,4),"	// A F U P
	"    attribution                  VARCHAR,"		// F, 4 alpha MPID
	"    executedShares               UINTEGER,"		// E C
	"    matchNumber                  UBIGINT,"		// E C P Q B
	"    printable                    VARCHAR,"		// C
	"    executionPrice               DECIMAL(16,4),"	// C
	"    cancelledShares              UINTEGER,"		// X
	// Q: Cross Trade
	"    crossPrice                   DECIMAL(16,4),"
	"    crossType                    VARCHAR,"		// Q I
	// I: Net Order Imbalance Indicator
	"    pairedShares                 UBIGINT,"
	"    imbalanceShares              UBIGINT,"
	"    imbalanceDirection           VARCHAR,"
	"    farPrice                     DECIMAL(16,4),"
	"    nearPrice                    DECIMAL(16,4),"
	"    currentReferencePrice        DECIMAL(16,4),"
	"    priceVariationIndicator      VARCHAR,"
	// N: Retail Price Improvement Indicator
	"    interestFlag                 VARCHAR,"
	// O: Direct Listing with Capital Raise
	"    openEligibilityStatus        VARCHAR,"
	"    minimumAllowablePrice        DECIMAL(16,4),"
	"    maximumAllowablePrice        DECIMAL(16,4),"
	"    nearExecutionPrice           DECIMAL(16,4),"
	"    nearExecutionTimeNS          UBIGINT,"
	"    lowerPriceRangeCollar        DECIMAL(16,4),"
	"    upperPriceRangeCollar        DECIMAL(16,4)"
	")";

//------------------------------------------------------------------------------
// multicast endpoints for TotalView-ITCH 5.0 (Nasdaq, NTX, PSX)
// see nasdaq_md_itch5.md section 8, captured 2026-07-04 from
// https://www.nasdaqtrader.com/Trader.aspx?id=FeedMIPS
//------------------------------------------------------------------------------

#define IP4(a,b,c,d)	(((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | (u32)(d))

typedef struct
{
	u32			group;		// multicast group, host byte order
	u16			port;		// udp destination port
	char		market;		// 'Q' = Nasdaq, 'T' = NTX, 'X' = PSX
	const char*	name;		// short human readable exchange + site name

} ITCH5Endpoint_t;

static const ITCH5Endpoint_t s_itch5Endpoint[] =
{
	// Nasdaq TotalView-ITCH 5.0
	{ IP4(233,187, 20,  0), 18070, 'Q', "Nasdaq Chicago A"           },
	{ IP4(233,187, 20, 64), 18070, 'Q', "Nasdaq Chicago B"           },
	{ IP4(233, 54, 12,111), 26477, 'Q', "Nasdaq New York A"          },	// also Hong Kong A
	{ IP4(233, 49,196,111), 26477, 'Q', "Nasdaq New York B"          },	// also Hong Kong B
	{ IP4(233, 54, 12,101), 26400, 'Q', "Nasdaq New York FPGA"       },
	{ IP4(233, 86,230,143), 26477, 'Q', "Nasdaq New Jersey uWave"    },
	{ IP4(233, 86,230,144), 26400, 'Q', "Nasdaq New Jersey uWave FPGA" },

	// NTX TotalView-ITCH 5.0
	{ IP4(233,187, 20, 32), 18070, 'T', "NTX Chicago A"              },
	{ IP4(233,187, 20, 40), 18070, 'T', "NTX Chicago B"              },
	{ IP4(233, 54, 12, 40), 25475, 'T', "NTX New York A"             },
	{ IP4(233, 49,196, 40), 25475, 'T', "NTX New York B"             },
	{ IP4(233, 54, 12, 33), 26400, 'T', "NTX New York FPGA"          },
	{ IP4(233, 86,230, 64), 25475, 'T', "NTX New Jersey uWave"       },

	// PSX TotalView-ITCH 5.0
	{ IP4(233,187, 20, 48), 18070, 'X', "PSX Chicago A"              },
	{ IP4(233,187, 20, 56), 18070, 'X', "PSX Chicago B"              },
	{ IP4(233, 54, 12, 45), 26477, 'X', "PSX New York A"             },
	{ IP4(233, 49,196, 45), 26477, 'X', "PSX New York B"             },
	{ IP4(233, 54, 12,123), 26400, 'X', "PSX New York FPGA"          },
};

#define ITCH5_ENDPOINT_COUNT	(sizeof(s_itch5Endpoint) / sizeof(s_itch5Endpoint[0]))

//------------------------------------------------------------------------------
// Protocol_ITCH5PacketClassify: returns true if the UDP destination matches a
// TotalView-ITCH 5.0 multicast group + port. ipDst and portDst are host
// byte order.
//------------------------------------------------------------------------------
bool Protocol_ITCH5PacketClassify(u32 ipDst, u16 portDst)
{
	for (u32 i = 0; i < ITCH5_ENDPOINT_COUNT; i++)
	{
		if ((s_itch5Endpoint[i].group == ipDst) && (s_itch5Endpoint[i].port == portDst))
		{
			return true;
		}
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

static INLINE u64 readBE48(const u8* p)
{
	return ((u64)readBE16(p) << 32) | (u64)readBE32(p + 2);
}

static INLINE u64 readBE64(const u8* p)
{
	return ((u64)readBE32(p) << 32) | (u64)readBE32(p + 4);
}

// price fields: unsigned integer with implied decimal places
static INLINE double readPrice4(const u8* p)
{
	return readBE32(p) / 1e4;
}

static INLINE double readPrice8(const u8* p)
{
	return readBE64(p) / 1e8;
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

//------------------------------------------------------------------------------
// decoded row: union of every column in the flat schema. varchar fields use
// an empty string to mean NULL; numeric fields use the fieldMask bit
//------------------------------------------------------------------------------

// bit positions in ITCH5Row_t.fieldMask for the optional numeric columns
enum
{
	ROW_ROUNDLOTSIZE = 0,
	ROW_ETPLEVERAGEFACTOR,
	ROW_MWCBLEVEL1,
	ROW_MWCBLEVEL2,
	ROW_MWCBLEVEL3,
	ROW_IPOQUOTATIONRELEASETIME,
	ROW_IPOPRICE,
	ROW_AUCTIONCOLLARREFERENCEPRICE,
	ROW_UPPERAUCTIONCOLLARPRICE,
	ROW_LOWERAUCTIONCOLLARPRICE,
	ROW_AUCTIONCOLLAREXTENSION,
	ROW_ORDERREFERENCENUMBER,
	ROW_ORIGINALORDERREFERENCENUMBER,
	ROW_NEWORDERREFERENCENUMBER,
	ROW_SHARES,
	ROW_PRICE,
	ROW_EXECUTEDSHARES,
	ROW_MATCHNUMBER,
	ROW_EXECUTIONPRICE,
	ROW_CANCELLEDSHARES,
	ROW_CROSSPRICE,
	ROW_PAIREDSHARES,
	ROW_IMBALANCESHARES,
	ROW_FARPRICE,
	ROW_NEARPRICE,
	ROW_CURRENTREFERENCEPRICE,
	ROW_MINIMUMALLOWABLEPRICE,
	ROW_MAXIMUMALLOWABLEPRICE,
	ROW_NEAREXECUTIONPRICE,
	ROW_NEAREXECUTIONTIMENS,
	ROW_LOWERPRICERANGECOLLAR,
	ROW_UPPERPRICERANGECOLLAR,
};

#define ROW_SET(r, f)	((r)->fieldMask |= (1ULL << (f)))
#define ROW_HAS(r, f)	(((r)->fieldMask >> (f)) & 1ULL)

typedef struct
{
	// common: always populated
	u64		pcapTS;
	char	moldSession[16];
	u64		moldSeqNo;
	char	msgType[2];
	u16		stockLocate;
	u16		trackingNumber;
	u64		timestampNS;

	u64		fieldMask;						// optional numeric column validity bits

	// varchar columns (empty string == NULL)
	char	eventCode[2];
	char	stock[16];
	char	marketCategory[2];
	char	financialStatusIndicator[2];
	char	roundLotsOnly[2];
	char	issueClassification[2];
	char	issueSubType[4];
	char	authenticity[2];
	char	shortSaleThresholdIndicator[2];
	char	ipoFlag[2];
	char	luldReferencePriceTier[2];
	char	etpFlag[2];
	char	inverseIndicator[2];
	char	tradingState[2];
	char	tradingActionReason[8];
	char	regSHOAction[2];
	char	mpid[8];
	char	primaryMarketMaker[2];
	char	marketMakerMode[2];
	char	marketParticipantState[2];
	char	mwcbBreachedLevel[2];
	char	ipoQuotationReleaseQualifier[2];
	char	marketCode[2];
	char	operationalHaltAction[2];
	char	buySellIndicator[2];
	char	attribution[8];
	char	printable[2];
	char	crossType[2];
	char	imbalanceDirection[2];
	char	priceVariationIndicator[2];
	char	interestFlag[2];
	char	openEligibilityStatus[2];

	// numeric columns, valid when the matching fieldMask bit is set
	u32		roundLotSize;
	u32		etpLeverageFactor;
	double	mwcbLevel1;
	double	mwcbLevel2;
	double	mwcbLevel3;
	u32		ipoQuotationReleaseTime;
	double	ipoPrice;
	double	auctionCollarReferencePrice;
	double	upperAuctionCollarPrice;
	double	lowerAuctionCollarPrice;
	u32		auctionCollarExtension;
	u64		orderReferenceNumber;
	u64		originalOrderReferenceNumber;
	u64		newOrderReferenceNumber;
	u64		shares;
	double	price;
	u32		executedShares;
	u64		matchNumber;
	double	executionPrice;
	u32		cancelledShares;
	double	crossPrice;
	u64		pairedShares;
	u64		imbalanceShares;
	double	farPrice;
	double	nearPrice;
	double	currentReferencePrice;
	double	minimumAllowablePrice;
	double	maximumAllowablePrice;
	double	nearExecutionPrice;
	u64		nearExecutionTimeNS;
	double	lowerPriceRangeCollar;
	double	upperPriceRangeCollar;

} ITCH5Row_t;

//------------------------------------------------------------------------------
// append helpers: NULL for empty strings / unset numeric fields
//------------------------------------------------------------------------------
static void appendStr(duckdb_appender a, const char* s)
{
	if (s[0])
	{
		duckdb_append_varchar(a, s);
	}
	else
	{
		duckdb_append_null(a);
	}
}

static void appendU32Opt(duckdb_appender a, ITCH5Row_t* r, u32 bit, u32 v)
{
	if (ROW_HAS(r, bit))
	{
		duckdb_append_uint32(a, v);
	}
	else
	{
		duckdb_append_null(a);
	}
}

static void appendU64Opt(duckdb_appender a, ITCH5Row_t* r, u32 bit, u64 v)
{
	if (ROW_HAS(r, bit))
	{
		duckdb_append_uint64(a, v);
	}
	else
	{
		duckdb_append_null(a);
	}
}

static void appendDblOpt(duckdb_appender a, ITCH5Row_t* r, u32 bit, double v)
{
	if (ROW_HAS(r, bit))
	{
		duckdb_append_double(a, v);
	}
	else
	{
		duckdb_append_null(a);
	}
}

//------------------------------------------------------------------------------
// itch5RowAppend: write one decoded row in exact schema column order
//------------------------------------------------------------------------------
static bool itch5RowAppend(Parquet_t* pq, ITCH5Row_t* r)
{
	duckdb_appender a = pq->appender;

	duckdb_appender_begin_row(a);

	// capture / transport layer
	duckdb_append_uint64(a, r->pcapTS);
	appendStr(a, r->moldSession);
	duckdb_append_uint64(a, r->moldSeqNo);
	duckdb_append_varchar(a, r->msgType);

	// common ITCH header
	duckdb_append_uint16(a, r->stockLocate);
	duckdb_append_uint16(a, r->trackingNumber);
	duckdb_append_uint64(a, r->timestampNS);

	// S: System Event
	appendStr(a, r->eventCode);

	// R: Stock Directory
	appendStr(a, r->stock);
	appendStr(a, r->marketCategory);
	appendStr(a, r->financialStatusIndicator);
	appendU32Opt(a, r, ROW_ROUNDLOTSIZE, r->roundLotSize);
	appendStr(a, r->roundLotsOnly);
	appendStr(a, r->issueClassification);
	appendStr(a, r->issueSubType);
	appendStr(a, r->authenticity);
	appendStr(a, r->shortSaleThresholdIndicator);
	appendStr(a, r->ipoFlag);
	appendStr(a, r->luldReferencePriceTier);
	appendStr(a, r->etpFlag);
	appendU32Opt(a, r, ROW_ETPLEVERAGEFACTOR, r->etpLeverageFactor);
	appendStr(a, r->inverseIndicator);

	// H: Stock Trading Action
	appendStr(a, r->tradingState);
	appendStr(a, r->tradingActionReason);

	// Y: Reg SHO Restriction
	appendStr(a, r->regSHOAction);

	// L: Market Participant Position
	appendStr(a, r->mpid);
	appendStr(a, r->primaryMarketMaker);
	appendStr(a, r->marketMakerMode);
	appendStr(a, r->marketParticipantState);

	// V/W: Market Wide Circuit Breaker
	appendDblOpt(a, r, ROW_MWCBLEVEL1, r->mwcbLevel1);
	appendDblOpt(a, r, ROW_MWCBLEVEL2, r->mwcbLevel2);
	appendDblOpt(a, r, ROW_MWCBLEVEL3, r->mwcbLevel3);
	appendStr(a, r->mwcbBreachedLevel);

	// K: IPO Quoting Period Update
	appendU32Opt(a, r, ROW_IPOQUOTATIONRELEASETIME, r->ipoQuotationReleaseTime);
	appendStr(a, r->ipoQuotationReleaseQualifier);
	appendDblOpt(a, r, ROW_IPOPRICE, r->ipoPrice);

	// J: LULD Auction Collar
	appendDblOpt(a, r, ROW_AUCTIONCOLLARREFERENCEPRICE, r->auctionCollarReferencePrice);
	appendDblOpt(a, r, ROW_UPPERAUCTIONCOLLARPRICE, r->upperAuctionCollarPrice);
	appendDblOpt(a, r, ROW_LOWERAUCTIONCOLLARPRICE, r->lowerAuctionCollarPrice);
	appendU32Opt(a, r, ROW_AUCTIONCOLLAREXTENSION, r->auctionCollarExtension);

	// h: Operational Halt
	appendStr(a, r->marketCode);
	appendStr(a, r->operationalHaltAction);

	// A/F/E/C/X/D/U/P: order book messages
	appendU64Opt(a, r, ROW_ORDERREFERENCENUMBER, r->orderReferenceNumber);
	appendU64Opt(a, r, ROW_ORIGINALORDERREFERENCENUMBER, r->originalOrderReferenceNumber);
	appendU64Opt(a, r, ROW_NEWORDERREFERENCENUMBER, r->newOrderReferenceNumber);
	appendStr(a, r->buySellIndicator);
	appendU64Opt(a, r, ROW_SHARES, r->shares);
	appendDblOpt(a, r, ROW_PRICE, r->price);
	appendStr(a, r->attribution);
	appendU32Opt(a, r, ROW_EXECUTEDSHARES, r->executedShares);
	appendU64Opt(a, r, ROW_MATCHNUMBER, r->matchNumber);
	appendStr(a, r->printable);
	appendDblOpt(a, r, ROW_EXECUTIONPRICE, r->executionPrice);
	appendU32Opt(a, r, ROW_CANCELLEDSHARES, r->cancelledShares);

	// Q: Cross Trade
	appendDblOpt(a, r, ROW_CROSSPRICE, r->crossPrice);
	appendStr(a, r->crossType);

	// I: Net Order Imbalance Indicator
	appendU64Opt(a, r, ROW_PAIREDSHARES, r->pairedShares);
	appendU64Opt(a, r, ROW_IMBALANCESHARES, r->imbalanceShares);
	appendStr(a, r->imbalanceDirection);
	appendDblOpt(a, r, ROW_FARPRICE, r->farPrice);
	appendDblOpt(a, r, ROW_NEARPRICE, r->nearPrice);
	appendDblOpt(a, r, ROW_CURRENTREFERENCEPRICE, r->currentReferencePrice);
	appendStr(a, r->priceVariationIndicator);

	// N: Retail Price Improvement Indicator
	appendStr(a, r->interestFlag);

	// O: Direct Listing with Capital Raise
	appendStr(a, r->openEligibilityStatus);
	appendDblOpt(a, r, ROW_MINIMUMALLOWABLEPRICE, r->minimumAllowablePrice);
	appendDblOpt(a, r, ROW_MAXIMUMALLOWABLEPRICE, r->maximumAllowablePrice);
	appendDblOpt(a, r, ROW_NEAREXECUTIONPRICE, r->nearExecutionPrice);
	appendU64Opt(a, r, ROW_NEAREXECUTIONTIMENS, r->nearExecutionTimeNS);
	appendDblOpt(a, r, ROW_LOWERPRICERANGECOLLAR, r->lowerPriceRangeCollar);
	appendDblOpt(a, r, ROW_UPPERPRICERANGECOLLAR, r->upperPriceRangeCollar);

	if (duckdb_appender_end_row(a) == DuckDBError)
	{
		fprintf(stderr, "itch5: append failed: %s\n", duckdb_appender_error(a));
		return false;
	}
	return true;
}

//------------------------------------------------------------------------------
// itch5MsgDecode: decode a single ITCH 5.0 message and append it as one row.
// returns false if the message is unknown or too short
//------------------------------------------------------------------------------
static bool itch5MsgDecode(Parquet_t* pq, u64 pcapTS, const char* session, u64 seqNo, const u8* msg, u32 msgLen)
{
	// common header: type(1) locate(2) tracking(2) timestamp(6)
	if (msgLen < 11)
	{
		return false;
	}

	ITCH5Row_t row;
	memset(&row, 0, sizeof(row));

	row.pcapTS = pcapTS;
	strncpy(row.moldSession, session, sizeof(row.moldSession) - 1);
	row.moldSeqNo = seqNo;
	row.msgType[0] = (char)msg[0];
	row.msgType[1] = 0;
	row.stockLocate = readBE16(msg + 1);
	row.trackingNumber = readBE16(msg + 3);
	row.timestampNS = readBE48(msg + 5);

	switch (msg[0])
	{
	case 'S':	// System Event (12)
		if (msgLen < 12) return false;
		alphaCopy(row.eventCode, msg + 11, 1);
		break;

	case 'R':	// Stock Directory (39)
		if (msgLen < 39) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.marketCategory, msg + 19, 1);
		alphaCopy(row.financialStatusIndicator, msg + 20, 1);
		row.roundLotSize = readBE32(msg + 21);
		ROW_SET(&row, ROW_ROUNDLOTSIZE);
		alphaCopy(row.roundLotsOnly, msg + 25, 1);
		alphaCopy(row.issueClassification, msg + 26, 1);
		alphaCopy(row.issueSubType, msg + 27, 2);
		alphaCopy(row.authenticity, msg + 29, 1);
		alphaCopy(row.shortSaleThresholdIndicator, msg + 30, 1);
		alphaCopy(row.ipoFlag, msg + 31, 1);
		alphaCopy(row.luldReferencePriceTier, msg + 32, 1);
		alphaCopy(row.etpFlag, msg + 33, 1);
		row.etpLeverageFactor = readBE32(msg + 34);
		ROW_SET(&row, ROW_ETPLEVERAGEFACTOR);
		alphaCopy(row.inverseIndicator, msg + 38, 1);
		break;

	case 'H':	// Stock Trading Action (25)
		if (msgLen < 25) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.tradingState, msg + 19, 1);
		// msg[20] reserved
		alphaCopy(row.tradingActionReason, msg + 21, 4);
		break;

	case 'Y':	// Reg SHO Restriction (20)
		if (msgLen < 20) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.regSHOAction, msg + 19, 1);
		break;

	case 'L':	// Market Participant Position (26)
		if (msgLen < 26) return false;
		alphaCopy(row.mpid, msg + 11, 4);
		alphaCopy(row.stock, msg + 15, 8);
		alphaCopy(row.primaryMarketMaker, msg + 23, 1);
		alphaCopy(row.marketMakerMode, msg + 24, 1);
		alphaCopy(row.marketParticipantState, msg + 25, 1);
		break;

	case 'V':	// MWCB Decline Level (35)
		if (msgLen < 35) return false;
		row.mwcbLevel1 = readPrice8(msg + 11);
		row.mwcbLevel2 = readPrice8(msg + 19);
		row.mwcbLevel3 = readPrice8(msg + 27);
		ROW_SET(&row, ROW_MWCBLEVEL1);
		ROW_SET(&row, ROW_MWCBLEVEL2);
		ROW_SET(&row, ROW_MWCBLEVEL3);
		break;

	case 'W':	// MWCB Status (12)
		if (msgLen < 12) return false;
		alphaCopy(row.mwcbBreachedLevel, msg + 11, 1);
		break;

	case 'K':	// IPO Quoting Period Update (28)
		if (msgLen < 28) return false;
		alphaCopy(row.stock, msg + 11, 8);
		row.ipoQuotationReleaseTime = readBE32(msg + 19);
		ROW_SET(&row, ROW_IPOQUOTATIONRELEASETIME);
		alphaCopy(row.ipoQuotationReleaseQualifier, msg + 23, 1);
		row.ipoPrice = readPrice4(msg + 24);
		ROW_SET(&row, ROW_IPOPRICE);
		break;

	case 'J':	// LULD Auction Collar (35)
		if (msgLen < 35) return false;
		alphaCopy(row.stock, msg + 11, 8);
		row.auctionCollarReferencePrice = readPrice4(msg + 19);
		row.upperAuctionCollarPrice = readPrice4(msg + 23);
		row.lowerAuctionCollarPrice = readPrice4(msg + 27);
		row.auctionCollarExtension = readBE32(msg + 31);
		ROW_SET(&row, ROW_AUCTIONCOLLARREFERENCEPRICE);
		ROW_SET(&row, ROW_UPPERAUCTIONCOLLARPRICE);
		ROW_SET(&row, ROW_LOWERAUCTIONCOLLARPRICE);
		ROW_SET(&row, ROW_AUCTIONCOLLAREXTENSION);
		break;

	case 'h':	// Operational Halt (21)
		if (msgLen < 21) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.marketCode, msg + 19, 1);
		alphaCopy(row.operationalHaltAction, msg + 20, 1);
		break;

	case 'A':	// Add Order - No MPID (36)
		if (msgLen < 36) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		alphaCopy(row.buySellIndicator, msg + 19, 1);
		row.shares = readBE32(msg + 20);
		ROW_SET(&row, ROW_SHARES);
		alphaCopy(row.stock, msg + 24, 8);
		row.price = readPrice4(msg + 32);
		ROW_SET(&row, ROW_PRICE);
		break;

	case 'F':	// Add Order - MPID Attribution (40)
		if (msgLen < 40) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		alphaCopy(row.buySellIndicator, msg + 19, 1);
		row.shares = readBE32(msg + 20);
		ROW_SET(&row, ROW_SHARES);
		alphaCopy(row.stock, msg + 24, 8);
		row.price = readPrice4(msg + 32);
		ROW_SET(&row, ROW_PRICE);
		alphaCopy(row.attribution, msg + 36, 4);
		break;

	case 'E':	// Order Executed (31)
		if (msgLen < 31) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		row.executedShares = readBE32(msg + 19);
		row.matchNumber = readBE64(msg + 23);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		ROW_SET(&row, ROW_EXECUTEDSHARES);
		ROW_SET(&row, ROW_MATCHNUMBER);
		break;

	case 'C':	// Order Executed With Price (36)
		if (msgLen < 36) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		row.executedShares = readBE32(msg + 19);
		row.matchNumber = readBE64(msg + 23);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		ROW_SET(&row, ROW_EXECUTEDSHARES);
		ROW_SET(&row, ROW_MATCHNUMBER);
		alphaCopy(row.printable, msg + 31, 1);
		row.executionPrice = readPrice4(msg + 32);
		ROW_SET(&row, ROW_EXECUTIONPRICE);
		break;

	case 'X':	// Order Cancel (23)
		if (msgLen < 23) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		row.cancelledShares = readBE32(msg + 19);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		ROW_SET(&row, ROW_CANCELLEDSHARES);
		break;

	case 'D':	// Order Delete (19)
		if (msgLen < 19) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		break;

	case 'U':	// Order Replace (35)
		if (msgLen < 35) return false;
		row.originalOrderReferenceNumber = readBE64(msg + 11);
		row.newOrderReferenceNumber = readBE64(msg + 19);
		row.shares = readBE32(msg + 27);
		row.price = readPrice4(msg + 31);
		ROW_SET(&row, ROW_ORIGINALORDERREFERENCENUMBER);
		ROW_SET(&row, ROW_NEWORDERREFERENCENUMBER);
		ROW_SET(&row, ROW_SHARES);
		ROW_SET(&row, ROW_PRICE);
		break;

	case 'P':	// Trade Non-Cross (44)
		if (msgLen < 44) return false;
		row.orderReferenceNumber = readBE64(msg + 11);
		ROW_SET(&row, ROW_ORDERREFERENCENUMBER);
		alphaCopy(row.buySellIndicator, msg + 19, 1);
		row.shares = readBE32(msg + 20);
		ROW_SET(&row, ROW_SHARES);
		alphaCopy(row.stock, msg + 24, 8);
		row.price = readPrice4(msg + 32);
		ROW_SET(&row, ROW_PRICE);
		row.matchNumber = readBE64(msg + 36);
		ROW_SET(&row, ROW_MATCHNUMBER);
		break;

	case 'Q':	// Cross Trade (40)
		if (msgLen < 40) return false;
		row.shares = readBE64(msg + 11);
		ROW_SET(&row, ROW_SHARES);
		alphaCopy(row.stock, msg + 19, 8);
		row.crossPrice = readPrice4(msg + 27);
		ROW_SET(&row, ROW_CROSSPRICE);
		row.matchNumber = readBE64(msg + 31);
		ROW_SET(&row, ROW_MATCHNUMBER);
		alphaCopy(row.crossType, msg + 39, 1);
		break;

	case 'B':	// Broken Trade (19)
		if (msgLen < 19) return false;
		row.matchNumber = readBE64(msg + 11);
		ROW_SET(&row, ROW_MATCHNUMBER);
		break;

	case 'I':	// Net Order Imbalance Indicator (50)
		if (msgLen < 50) return false;
		row.pairedShares = readBE64(msg + 11);
		row.imbalanceShares = readBE64(msg + 19);
		ROW_SET(&row, ROW_PAIREDSHARES);
		ROW_SET(&row, ROW_IMBALANCESHARES);
		alphaCopy(row.imbalanceDirection, msg + 27, 1);
		alphaCopy(row.stock, msg + 28, 8);
		row.farPrice = readPrice4(msg + 36);
		row.nearPrice = readPrice4(msg + 40);
		row.currentReferencePrice = readPrice4(msg + 44);
		ROW_SET(&row, ROW_FARPRICE);
		ROW_SET(&row, ROW_NEARPRICE);
		ROW_SET(&row, ROW_CURRENTREFERENCEPRICE);
		alphaCopy(row.crossType, msg + 48, 1);
		alphaCopy(row.priceVariationIndicator, msg + 49, 1);
		break;

	case 'N':	// Retail Price Improvement Indicator (20)
		if (msgLen < 20) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.interestFlag, msg + 19, 1);
		break;

	case 'O':	// Direct Listing with Capital Raise (48)
		if (msgLen < 48) return false;
		alphaCopy(row.stock, msg + 11, 8);
		alphaCopy(row.openEligibilityStatus, msg + 19, 1);
		row.minimumAllowablePrice = readPrice4(msg + 20);
		row.maximumAllowablePrice = readPrice4(msg + 24);
		row.nearExecutionPrice = readPrice4(msg + 28);
		row.nearExecutionTimeNS = readBE64(msg + 32);
		row.lowerPriceRangeCollar = readPrice4(msg + 40);
		row.upperPriceRangeCollar = readPrice4(msg + 44);
		ROW_SET(&row, ROW_MINIMUMALLOWABLEPRICE);
		ROW_SET(&row, ROW_MAXIMUMALLOWABLEPRICE);
		ROW_SET(&row, ROW_NEAREXECUTIONPRICE);
		ROW_SET(&row, ROW_NEAREXECUTIONTIMENS);
		ROW_SET(&row, ROW_LOWERPRICERANGECOLLAR);
		ROW_SET(&row, ROW_UPPERPRICERANGECOLLAR);
		break;

	default:
		// unknown message type
		return false;
	}

	return itch5RowAppend(pq, &row);
}

//------------------------------------------------------------------------------
// Protocol_ITCH5Decode: decode one MoldUDP64 packet (UDP payload) and append
// every contained ITCH message to the parquet table. returns the number of
// messages decoded
//------------------------------------------------------------------------------
u32 Protocol_ITCH5Decode(Parquet_t* pq, u64 pcapTS, const u8* payload, u32 payloadLen)
{
	// MoldUDP64 header: session(10) seqNo(8) msgCount(2)
	if (payloadLen < 20)
	{
		return 0;
	}

	char session[16];
	alphaCopy(session, payload, 10);
	u64 seqNo = readBE64(payload + 10);
	u32 msgCount = readBE16(payload + 18);

	// heartbeat / end of session carry no message blocks
	if ((msgCount == 0) || (msgCount == 0xffff))
	{
		return 0;
	}

	const u8* ptr = payload + 20;
	const u8* end = payload + payloadLen;

	u32 decoded = 0;
	for (u32 i = 0; i < msgCount; i++)
	{
		if (ptr + 2 > end)
		{
			break;
		}
		u32 msgLen = readBE16(ptr);
		ptr += 2;

		if (ptr + msgLen > end)
		{
			break;
		}

		if (itch5MsgDecode(pq, pcapTS, session, seqNo + i, ptr, msgLen))
		{
			decoded++;
		}
		ptr += msgLen;
	}

	return decoded;
}

//------------------------------------------------------------------------------
// Protocol_ITCH5SchemaCreate: create the ITCH 5.0 table and appender on the context
//------------------------------------------------------------------------------
bool Protocol_ITCH5SchemaCreate(Parquet_t* pq)
{
	duckdb_result result;
	if (duckdb_query(pq->con, s_schemaSQL, &result) == DuckDBError)
	{
		fprintf(stderr, "itch5: failed to create schema: %s\n", duckdb_result_error(&result));
		duckdb_destroy_result(&result);
		return false;
	}
	duckdb_destroy_result(&result);

	pq->tableName = ITCH5_TABLE_NAME;

	if (duckdb_appender_create(pq->con, NULL, ITCH5_TABLE_NAME, &pq->appender) == DuckDBError)
	{
		fprintf(stderr, "itch5: failed to create appender\n");
		return false;
	}

	return true;
}
