#pragma once

//------------------------------------------------------------------------------
//
// fCapture.h
//
// per packet capture layer metadata passed from the packet loop (main.c) to
// the protocol decoders: pcap timestamp, full 5-tuple + VLAN tags and the
// arista 7130 (metamako) timestamp trailer.
//
// every protocol parquet schema starts with the same frame_* capture layer
// columns (CAPTURE_SCHEMA_COLUMNS), written in exact column order by
// packetInfoAppend.
//
//------------------------------------------------------------------------------

#include <stdio.h>

#include "fTypes.h"
#include "fParquet.h"
#include "parq.h"

#define VLAN_NONE	0xffff		// vlanOuter / vlanInner: tag not present

typedef struct
{
	u64		pcapTS;				// pcap timestamp, ns since epoch

	// 5-tuple + vlan (host byte order)
	u32		ipSrc;
	u32		ipDst;
	u16		portSrc;
	u16		portDst;
	u8		ipProto;
	u16		vlanOuter;			// outermost 802.1Q ID, VLAN_NONE if untagged
	u16		vlanInner;			// innermost ID for QinQ, VLAN_NONE if single tagged / untagged

	// arista 7130 (metamako) trailer appended after the IP datagram at the
	// frame end; footerValid = trailer found on this frame
	bool	footerValid;
	u32		footerSec;			// trailer seconds since epoch
	u32		footerNS;			// trailer nanoseconds
	u8		footerFlags;		// bit 0: original FCS valid
	u16		footerDeviceID;		// capture device identifier
	u8		footerPortID;		// capture device port

	// packet provenance for capture side extraction: with FMAD chunked
	// stream input these address the packet on the capture storage, with
	// plain pcap input both are 0
	const char*	hostname;		// capture device hostname (gethostname at startup)
	u64		pktBlock;			// capture side chunk id from the FMAD chunk header
	u32		pktOffset;			// physical byte offset of the packet inside the stored chunk

} PacketInfo_t;

// capture layer columns common to every protocol schema (ParquetColumn_t
// initializer list fragment). column names are grouped by where the field is
// derived from: frame_* = the captured frame itself (pcap record, headers,
// trailer); the protocol schemas continue with hdr_* (transport header) and
// msg_* (business message) columns. pb = packet broker (arista 7130); pbTS
// is the trailer timestamp as ns since epoch; all pb/vlan columns are NULL when the frame carries no
// trailer / tag
#define CAPTURE_SCHEMA_COLUMNS \
	{ "frame_ts",                     PARQUET_TYPE_U64   }, \
	{ "frame_ipSrc",                  PARQUET_TYPE_STRING}, \
	{ "frame_ipDst",                  PARQUET_TYPE_STRING}, \
	{ "frame_portSrc",                PARQUET_TYPE_U16   }, \
	{ "frame_portDst",                PARQUET_TYPE_U16   }, \
	{ "frame_ipProto",                PARQUET_TYPE_U8    }, \
	{ "frame_vlanOuter",              PARQUET_TYPE_U16   }, \
	{ "frame_vlanInner",              PARQUET_TYPE_U16   }, \
	{ "frame_pbTS",                   PARQUET_TYPE_U64   }, \
	{ "frame_pbFlags",                PARQUET_TYPE_U8    }, \
	{ "frame_pbDeviceID",             PARQUET_TYPE_U16   }, \
	{ "frame_pbPortID",               PARQUET_TYPE_U8    }, \
	{ "frame_hostname",               PARQUET_TYPE_STRING}, \
	{ "frame_pkt_block",              PARQUET_TYPE_U64   }, \
	{ "frame_pkt_offset",             PARQUET_TYPE_U32    },

// dotted quad string from a host byte order IPv4 address
static INLINE void ip4Str(u32 ip, char* dst)
{
	sprintf(dst, "%u.%u.%u.%u", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}

// append the capture layer columns in exact CAPTURE_SCHEMA_COLUMNS order
static INLINE void packetInfoAppend(Parquet_t* pq, const PacketInfo_t* pkt)
{
	parquetAppendU64(pq, pkt->pcapTS);

	char ipStr[20];
	ip4Str(pkt->ipSrc, ipStr);
	parquetAppendStr(pq, ipStr);
	ip4Str(pkt->ipDst, ipStr);
	parquetAppendStr(pq, ipStr);

	parquetAppendU16(pq, pkt->portSrc);
	parquetAppendU16(pq, pkt->portDst);
	parquetAppendU8(pq, pkt->ipProto);

	if (pkt->vlanOuter != VLAN_NONE)
	{
		parquetAppendU16(pq, pkt->vlanOuter);
	}
	else
	{
		parquetAppendNull(pq);
	}
	if (pkt->vlanInner != VLAN_NONE)
	{
		parquetAppendU16(pq, pkt->vlanInner);
	}
	else
	{
		parquetAppendNull(pq);
	}

	if (pkt->footerValid)
	{
		parquetAppendU64(pq, (u64)pkt->footerSec * k1E9 + pkt->footerNS);
		parquetAppendU8(pq, pkt->footerFlags);
		parquetAppendU16(pq, pkt->footerDeviceID);
		parquetAppendU8(pq, pkt->footerPortID);
	}
	else
	{
		parquetAppendNull(pq);
		parquetAppendNull(pq);
		parquetAppendNull(pq);
		parquetAppendNull(pq);
	}

	parquetAppendStr(pq, pkt->hostname);
	parquetAppendU64(pq, pkt->pktBlock);
	parquetAppendU32(pq, pkt->pktOffset);
}
