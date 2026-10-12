//------------------------------------------------------------------------------
//
// fix42.c
//
// FIX 4.2 protocol decoder (generic tag=value order flow over TCP).
//
// Parquet schema creation for the flat FIX output table: one row per FIX
// message (admin and application messages alike), ONE COLUMN PER FIX TAG
// (fix_1 .. fix_1024, typed from the FIX 4.2 dictionary, generated into
// fix42_schema.h). See fix42.md section 7 for the full specification.
//
// Protocol specifics handled here (fix42.md sections 1-6):
// - TCP based (.ipProto = IPV4_PROTO_TCP): decode() receives reassembled in
//   order stream segments from src/tcpstream.c. FIX messages span segment
//   boundaries, a per flow partial message accumulator lives in the
//   endpoint. payload=NULL = stream reset
// - framing: "8=FIX...<SOH>9=<BodyLength><SOH>" prefix + BodyLength +
//   "10=nnn<SOH>" trailer. trailer position is verified; any inconsistency
//   resyncs by scanning for the next "8=FIX" (mid stream captures and non
//   FIX flows produce no rows, only discarded bytes)
// - checksum: sum mod 256 of every byte before "10=", computed BEFORE the
//   tokenizer NUL terminates the values in place -> hdr_checksumValid
//   (bad checksum rows are emitted flagged, not dropped)
// - repeating groups are NOT exploded: first occurrence of a tag wins,
//   drops are counted in hdr_dupTagCount. tags > FIX_TAG_MAX are dropped
//   and counted in hdr_overflowTagCount
// - LENGTH/DATA pairs: a DATA value's byte length comes from the
//   immediately preceding LENGTH tag (it may contain SOH); implausible
//   lengths fall back to the SOH scan
// - FIX has NO well known endpoints: the classifier matches every TCP flow
//   and the protocol registers .noAutoDetect = true, so it never claims
//   flows in -p auto mode - it must be selected explicitly with -p fix42
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fTypes.h"
#include "fParquet.h"
#include "parq.h"
#include "fix42.h"
#include "fix42_schema.h"

#define FIX_TABLE_NAME			"fix"

#define FIX_SOH					0x01		// tag=value pair delimiter
#define FIX_ACCUM_MAX			kKB(256)	// accumulator cap; > max frame, overflow = garbage length prefix
#define FIX_BODY_MAX			kKB(192)	// BodyLength sanity cap (a real FIX message is far smaller)
#define FIX_HEADER_SCAN_MAX		32			// "8=<BeginString>SOH9=<digits>SOH" must fit in this prefix
#define FIX_TRAILER_LEN			7			// "10=nnn" + SOH

//------------------------------------------------------------------------------
// per message tag store: value pointer per tag, generation stamped so no per
// message clearing is needed. one protocol is active per run, so file scope
// statics (not per flow) are safe
//------------------------------------------------------------------------------
static const char*	s_tagVal[FIX_TAG_MAX + 1];		// NUL terminated value, valid when the generation matches
static u32			s_tagGen[FIX_TAG_MAX + 1];		// generation stamp, == s_gen -> tag present in this message
static u32			s_gen = 0;						// current message generation

//------------------------------------------------------------------------------
// fixRowAppend: write one decoded message in exact schema column order:
// capture layer + transport metadata + one append per tag column
//------------------------------------------------------------------------------
static bool fixRowAppend(Parquet_t* pq, const PacketInfo_t* pkt, u8 checksumValid, u16 dupTagCount, u16 overflowTagCount)
{
	parquetRowBegin(pq);

	// capture layer (5-tuple + vlan + packet broker trailer)
	packetInfoAppend(pq, pkt);

	// transport layer (FIX framing metadata)
	parquetAppendU8(pq, checksumValid);
	parquetAppendU16(pq, dupTagCount);
	parquetAppendU16(pq, overflowTagCount);

	// one column per tag
	for (u32 tag = 1; tag <= FIX_TAG_MAX; tag++)
	{
		if (s_tagGen[tag] != s_gen)
		{
			parquetAppendNull(pq);
			continue;
		}

		switch (s_tagClass[tag])
		{
		case FIX_CLASS_S64:
		case FIX_CLASS_LENGTH:
		{
			char* end = NULL;
			s64 v = strtoll(s_tagVal[tag], &end, 10);
			if (end == s_tagVal[tag])
			{
				parquetAppendNull(pq);
			}
			else
			{
				parquetAppendS64(pq, v);
			}
			break;
		}
		case FIX_CLASS_DOUBLE:
		{
			char* end = NULL;
			double v = strtod(s_tagVal[tag], &end);
			if (end == s_tagVal[tag])
			{
				parquetAppendNull(pq);
			}
			else
			{
				parquetAppendDouble(pq, v);
			}
			break;
		}
		default:
			// FIX_CLASS_STR / FIX_CLASS_DATA; empty value appends NULL
			parquetAppendStr(pq, s_tagVal[tag]);
			break;
		}
	}

	return parquetRowEnd(pq);
}

//------------------------------------------------------------------------------
// fixMsgTokenize: split one complete frame into tag=value pairs, NUL
// terminating and sanitizing the values IN PLACE (the frame lives in the
// flow's accumulator which is consumed afterwards). first occurrence of a
// tag wins; duplicate and overflow (> FIX_TAG_MAX) tags are counted
//------------------------------------------------------------------------------
static void fixMsgTokenize(u8* frame, u32 total, u16* dupTagCount, u16* overflowTagCount)
{
	s_gen++;

	u32 dup = 0;
	u32 overflow = 0;
	s64 pendingDataLen = -1;					// armed by a LENGTH tag for the next DATA tag

	u8* p = frame;
	u8* end = frame + total;
	while (p < end)
	{
		// tag number: ASCII digits up to '='
		u32 tag = 0;
		bool digit = false;
		while ((p < end) && (*p >= '0') && (*p <= '9'))
		{
			if (tag <= FIX_TAG_MAX)				// clamp guard: keeps huge tags > FIX_TAG_MAX without overflow
			{
				tag = tag * 10 + (*p - '0');
			}
			digit = true;
			p++;
		}
		if (!digit || (p >= end) || (*p != '='))
		{
			// malformed pair: skip to the byte after the next SOH
			while ((p < end) && (*p != FIX_SOH))
			{
				p++;
			}
			p++;
			pendingDataLen = -1;
			continue;
		}
		p++;									// skip '='

		u8* val = p;
		u8* valEnd;
		if ((tag >= 1) && (tag <= FIX_TAG_MAX) && (s_tagClass[tag] == FIX_CLASS_DATA) &&
			(pendingDataLen >= 0) && (val + pendingDataLen < end) && (val[pendingDataLen] == FIX_SOH))
		{
			// DATA field: consume exactly the armed byte count (the value may
			// contain SOH); the byte after it must be the delimiter
			valEnd = val + pendingDataLen;
		}
		else
		{
			valEnd = val;
			while ((valEnd < end) && (*valEnd != FIX_SOH))
			{
				valEnd++;
			}
			if (valEnd >= end)
			{
				// no delimiter before frame end (frame verification guarantees
				// a final SOH, so this only happens on garbage): clamp
				valEnd = end - 1;
			}
		}

		// sanitize: stored values must be printable text (DATA fields can
		// carry arbitrary bytes)
		for (u8* c = val; c < valEnd; c++)
		{
			if ((*c < 0x20) || (*c > 0x7e))
			{
				*c = '.';
			}
		}
		*valEnd = 0;							// NUL terminate in place (overwrites the SOH)

		// arm the DATA byte length when this tag is a LENGTH field, one shot
		pendingDataLen = -1;
		if ((tag >= 1) && (tag <= FIX_TAG_MAX))
		{
			if (s_tagClass[tag] == FIX_CLASS_LENGTH)
			{
				char* lenEnd = NULL;
				s64 v = strtoll((const char*)val, &lenEnd, 10);
				if ((lenEnd != (char*)val) && (v >= 0))
				{
					pendingDataLen = v;
				}
			}

			if (s_tagGen[tag] == s_gen)
			{
				dup++;							// repeating group: first occurrence wins
			}
			else
			{
				s_tagGen[tag] = s_gen;
				s_tagVal[tag] = (const char*)val;
			}
		}
		else
		{
			overflow++;							// tag 0 or > FIX_TAG_MAX: dropped
		}

		p = valEnd + 1;
	}

	*dupTagCount      = (dup      > 0xffff) ? 0xffff : (u16)dup;
	*overflowTagCount = (overflow > 0xffff) ? 0xffff : (u16)overflow;
}

//------------------------------------------------------------------------------
// fixFrameDecode: one complete verified frame = ONE ROW. computes the
// checksum before the tokenizer mutates the frame, then tokenizes and
// appends. returns rows written (0 / 1)
//------------------------------------------------------------------------------
static u32 fixFrameDecode(Parquet_t* pq, const PacketInfo_t* pkt, u8* frame, u32 total)
{
	// checksum: sum mod 256 of every byte before the "10=nnn<SOH>" trailer
	u32 sum = 0;
	for (u32 i = 0; i < total - FIX_TRAILER_LEN; i++)
	{
		sum += frame[i];
	}
	sum &= 0xff;

	u16 dupTagCount = 0;
	u16 overflowTagCount = 0;
	fixMsgTokenize(frame, total, &dupTagCount, &overflowTagCount);

	u8 checksumValid = 0;
	if (s_tagGen[10] == s_gen)
	{
		char* end = NULL;
		u32 wire = (u32)strtoul(s_tagVal[10], &end, 10);
		if ((end != s_tagVal[10]) && ((wire & 0xff) == sum))
		{
			checksumValid = 1;
		}
	}

	return fixRowAppend(pq, pkt, checksumValid, dupTagCount, overflowTagCount) ? 1 : 0;
}

//------------------------------------------------------------------------------
// fixResyncScan: the stream is not on a message boundary (mid stream capture
// start, corrupt frame, or a non FIX flow - the classifier matches every TCP
// flow). find the next "8=FIX" marker at or after from; when there is none,
// keep only the last 4 bytes (a possible split "8=FI" prefix) for the next
// segment. returns the new parse position, always > the caller's position
//------------------------------------------------------------------------------
static u32 fixResyncScan(const u8* buf, u32 from, u32 len)
{
	for (u32 i = from; i + 5 <= len; i++)
	{
		if ((buf[i] == '8') && (memcmp(buf + i, "8=FIX", 5) == 0))
		{
			return i;
		}
	}
	return (len - from > 4) ? (len - 4) : from;
}

//------------------------------------------------------------------------------
// Protocol_FIX42Decode: consume one reassembled TCP stream segment. FIX
// messages are accumulated across segments and decoded once complete.
// payload=NULL length=0 = stream reset (new SYN): discard the partial
// message. returns the number of FIX messages decoded
//------------------------------------------------------------------------------
u32 Protocol_FIX42Decode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpointArg, const u8* payload, u32 payloadLen)
{
	FIXEndpoint_t* endpoint = (FIXEndpoint_t*)endpointArg;

	// stream reset: new TCP connection
	if (payload == NULL)
	{
		endpoint->frameLen = 0;
		return 0;
	}

	// append the segment to the partial message accumulator
	u32 need = endpoint->frameLen + payloadLen;
	if (need > FIX_ACCUM_MAX)
	{
		// only reachable on garbage length prefixes (FIX_BODY_MAX bounds any
		// real frame below the cap): resync from scratch
		endpoint->frameLen = 0;
		return 0;
	}
	if (need > endpoint->frameMax)
	{
		u32 max = (endpoint->frameMax == 0) ? (u32)kKB(4) : endpoint->frameMax;
		while (max < need)
		{
			max *= 2;
		}
		u8* buf = realloc(endpoint->frameBuf, max);
		if (!buf)
		{
			fprintf(stderr, "fix42: failed to allocate %u byte frame buffer\n", max);
			exit(1);
		}
		endpoint->frameBuf = buf;
		endpoint->frameMax = max;
	}
	memcpy(endpoint->frameBuf + endpoint->frameLen, payload, payloadLen);
	endpoint->frameLen += payloadLen;

	// consume complete messages from the front
	u32 decoded = 0;
	u32 pos = 0;
	u8* buf = endpoint->frameBuf;
	u32 len = endpoint->frameLen;
	while (true)
	{
		u32 avail = len - pos;
		if (avail < 5)
		{
			break;								// not enough for the boundary marker
		}

		// every message starts with "8=FIX"
		if (memcmp(buf + pos, "8=FIX", 5) != 0)
		{
			pos = fixResyncScan(buf, pos + 1, len);
			continue;
		}

		// parse "8=<BeginString><SOH>9=<BodyLength><SOH>", both within the
		// first FIX_HEADER_SCAN_MAX bytes of the frame
		u32 scanMax = (avail < FIX_HEADER_SCAN_MAX) ? avail : FIX_HEADER_SCAN_MAX;
		u32 i = 5;
		while ((i < scanMax) && (buf[pos + i] != FIX_SOH))
		{
			i++;
		}
		if (i >= scanMax)
		{
			if (avail >= FIX_HEADER_SCAN_MAX)
			{
				pos = fixResyncScan(buf, pos + 1, len);		// no SOH in a sane prefix: garbage
				continue;
			}
			break;								// need more data
		}
		i++;

		if (i + 2 > avail)
		{
			break;								// need more data for "9="
		}
		if ((buf[pos + i] != '9') || (buf[pos + i + 1] != '='))
		{
			pos = fixResyncScan(buf, pos + 1, len);
			continue;
		}
		i += 2;

		u64 bodyLen = 0;
		bool digit = false;
		while ((i < scanMax) && (buf[pos + i] >= '0') && (buf[pos + i] <= '9'))
		{
			bodyLen = bodyLen * 10 + (buf[pos + i] - '0');
			if (bodyLen > FIX_BODY_MAX)
			{
				bodyLen = FIX_BODY_MAX + 1;		// sticky overflow, fails the sanity check below
			}
			digit = true;
			i++;
		}
		if (i >= scanMax)
		{
			if (avail >= FIX_HEADER_SCAN_MAX)
			{
				pos = fixResyncScan(buf, pos + 1, len);
				continue;
			}
			break;								// need more data, digits may continue
		}
		if (!digit || (buf[pos + i] != FIX_SOH) || (bodyLen > FIX_BODY_MAX))
		{
			pos = fixResyncScan(buf, pos + 1, len);
			continue;
		}
		i++;									// past the SOH, i = body start

		// whole frame = header prefix + body + "10=nnn<SOH>" trailer
		u64 total = (u64)i + bodyLen + FIX_TRAILER_LEN;
		if (total > avail)
		{
			break;								// incomplete, wait for the next segment
		}

		// verify the trailer position: BodyLength must put "10=" exactly at
		// the frame end. a lying BodyLength = corrupt stream = resync
		if ((memcmp(buf + pos + total - FIX_TRAILER_LEN, "10=", 3) != 0) || (buf[pos + total - 1] != FIX_SOH))
		{
			pos = fixResyncScan(buf, pos + 1, len);
			continue;
		}

		decoded += fixFrameDecode(pq, pkt, buf + pos, (u32)total);
		pos += total;
	}

	// keep the incomplete tail for the next segment
	if (pos > 0)
	{
		memmove(buf, buf + pos, len - pos);
		endpoint->frameLen = len - pos;
	}

	return decoded;
}

//------------------------------------------------------------------------------
// Protocol_FIX42PacketClassify: FIX has no well known endpoints (every
// counterparty pair negotiates its own addresses/ports), so every TCP flow
// matches and the framing layer is the content filter. the protocol
// registers .noAutoDetect: this classifier never runs in -p auto mode
//------------------------------------------------------------------------------
bool Protocol_FIX42PacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpointArg)
{
	(void)ipSrc;
	(void)portSrc;
	(void)ipDst;
	(void)portDst;

	memset(endpointArg, 0, sizeof(FIXEndpoint_t));
	return true;
}

//------------------------------------------------------------------------------
// Protocol_FIX42SchemaCreate: create the FIX table and appender on the context
//------------------------------------------------------------------------------
bool Protocol_FIX42SchemaCreate(Parquet_t* pq)
{
	return parquetSchemaCreate(pq, FIX_TABLE_NAME, s_schema, sizeof(s_schema) / sizeof(s_schema[0]));
}

//------------------------------------------------------------------------------
// protocol registration: self registers at program start (see fProtocol.h),
// main.c and the Makefile carry no per protocol knowledge
//------------------------------------------------------------------------------
static Protocol_t s_protocolDesc =
{
	.name         = "fix42",
	.shortName    = "fix",
	.statsName    = "FIX42",
	.description  = "FIX 4.2 tag=value order flow (generic TCP, no autodetect: requires -p fix42)",
	.ipProto      = IPV4_PROTO_TCP,
	.noAutoDetect = true,
	.endpointSize = sizeof(FIXEndpoint_t),
	.schemaCreate = Protocol_FIX42SchemaCreate,
	.classify     = Protocol_FIX42PacketClassify,
	.decode       = Protocol_FIX42Decode,
};

static void __attribute__((constructor)) fix42Register(void)
{
	Protocol_Register(&s_protocolDesc);
}
