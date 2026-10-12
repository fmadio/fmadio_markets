//------------------------------------------------------------------------------
//
// efilatency.c
//
// EFI latency test packet protocol decoder.
//
// REVERSE ENGINEERED protocol (no vendor specification): fixed 64 byte UDP
// payload carrying a u64 big endian sequence number at offset 0 and a 1 byte
// ASCII phase indicator at offset 8 ('W' = warmup, 'N' = normal, inferred),
// zero padded to 64 bytes. each sequence number is transmitted on two paths
// (two source MACs / capture ports), so pairing rows by msg_seqNo and
// differencing frame_ts / frame_pbTS measures the path latency. one row per
// datagram. see efilatency.md for the full specification.
//
//------------------------------------------------------------------------------

#include <stdio.h>

#include "fTypes.h"
#include "fParquet.h"
#include "parq.h"
#include "efilatency.h"

#define EFILAT_TABLE_NAME	"efilatency"

#define EFILAT_UDP_PORT		8080	// source AND destination port of the test flow
#define EFILAT_MSG_SIZE		64		// fixed UDP payload size on the wire
#define EFILAT_MSG_MIN		9		// minimum decodable: seqNo(8) + indicator(1)

// flat schema: capture layer + the two message fields. no hdr_* group, the
// protocol has no transport header and the classifier carries no endpoint
// context
static const ParquetColumn_t s_schema[] =
{
	// capture layer (5-tuple + vlan + arista 7130 trailer), see fCapture.h
	CAPTURE_SCHEMA_COLUMNS
	// message
	{ "msg_seqNo",                          PARQUET_TYPE_U64          },	// sequence number, starts at 1, +1 per message (payload offset 0)
	{ "msg_indicator",                      PARQUET_TYPE_STRING       },	// 1 char ASCII phase indicator, observed 'W' / 'N' (payload offset 8)
};

//------------------------------------------------------------------------------
// Protocol_EFILATPacketClassify: returns true if the UDP flow is an
// efilatency test flow. there is no multicast group plan or reserved subnet
// (the reference capture is unicast IP with a broadcast MAC), so the match is
// source AND destination port 8080; the fixed payload shape is enforced per
// datagram in decode. ports are host byte order.
//------------------------------------------------------------------------------
bool Protocol_EFILATPacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpoint)
{
	(void)ipSrc;
	(void)ipDst;
	(void)endpoint;		// efilatency needs no endpoint context

	return (portSrc == EFILAT_UDP_PORT) && (portDst == EFILAT_UDP_PORT);
}

//------------------------------------------------------------------------------
// big endian field readers
//------------------------------------------------------------------------------
static INLINE u32 readBE32(const u8* p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static INLINE u64 readBE64(const u8* p)
{
	return ((u64)readBE32(p) << 32) | (u64)readBE32(p + 4);
}

//------------------------------------------------------------------------------
// Protocol_EFILATDecode: decode one efilatency datagram into one parquet row.
// payloads shorter than seqNo + indicator are skipped; longer or shorter than
// the fixed 64 bytes (or with non zero padding) still decode, only the two
// defined fields are read (future runs may use the padding)
//------------------------------------------------------------------------------
u32 Protocol_EFILATDecode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpoint, const u8* payload, u32 payloadLen)
{
	(void)endpoint;

	if (payloadLen < EFILAT_MSG_MIN)
	{
		return 0;
	}

	parquetRowBegin(pq);

	// capture layer columns (see fCapture.h)
	packetInfoAppend(pq, pkt);

	// msg_seqNo
	parquetAppendU64(pq, readBE64(payload + 0));

	// msg_indicator: 1 ASCII char; a 0x00 byte becomes an empty string which
	// the writer stores as NULL
	char indicator[2];
	indicator[0] = (char)payload[8];
	indicator[1] = 0;
	parquetAppendStr(pq, indicator);

	if (!parquetRowEnd(pq))
	{
		return 0;
	}

	return 1;
}

//------------------------------------------------------------------------------
// Protocol_EFILATSchemaCreate: create the efilatency table and appender on the context
//------------------------------------------------------------------------------
bool Protocol_EFILATSchemaCreate(Parquet_t* pq)
{
	return parquetSchemaCreate(pq, EFILAT_TABLE_NAME, s_schema, sizeof(s_schema) / sizeof(s_schema[0]));
}

//------------------------------------------------------------------------------
// protocol registration: self registers at program start (see fProtocol.h),
// main.c and the Makefile carry no per protocol knowledge
//------------------------------------------------------------------------------
static Protocol_t s_protocolDesc =
{
	.name         = "efilatency",
	.shortName    = "efilat",
	.statsName    = "EFILAT",
	.description  = "EFI latency test packets (seqNo + indicator)",
	.ipProto      = IPV4_PROTO_UDP,
	.endpointSize = 0,
	.schemaCreate = Protocol_EFILATSchemaCreate,
	.classify     = Protocol_EFILATPacketClassify,
	.decode       = Protocol_EFILATDecode,
};

static void __attribute__((constructor)) efilatRegister(void)
{
	Protocol_Register(&s_protocolDesc);
}
