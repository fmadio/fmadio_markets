#pragma once

//------------------------------------------------------------------------------
//
// fix42.h
//
// FIX 4.2 protocol decoder interface. TCP based: the decoder receives
// reassembled in order stream segments and keeps its per flow FIX message
// framing state in the endpoint. one parquet row per FIX message, one column
// per FIX tag (fix_1 .. fix_1024, see fix42_schema.h / fix42.md).
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fParquet.h"
#include "fCapture.h"
#include "fProtocol.h"

// classification result + per flow stream state (mutable, lives in the flow
// entry, <= PROTOCOL_ENDPOINT_MAX bytes)
typedef struct
{
	// partial FIX message accumulator: messages span TCP segments
	u8*		frameBuf;			// lazily allocated
	u32		frameLen;			// bytes accumulated
	u32		frameMax;			// allocated size

} FIXEndpoint_t;

// creates the flat FIX parquet schema and appender on the context
bool Protocol_FIX42SchemaCreate(Parquet_t* pq);

// FIX has no well known endpoints: matches EVERY TCP flow (the protocol
// registers .noAutoDetect so this only runs when -p fix42 is explicit);
// the framing layer is the content filter
bool Protocol_FIX42PacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpoint);

// decodes one reassembled TCP stream segment (FIX messages, possibly
// partial) writing every contained FIX message as a row into the parquet
// table. payload=NULL length=0 = stream reset (new SYN), discards framing
// state. returns the message count decoded
u32 Protocol_FIX42Decode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpoint, const u8* payload, u32 payloadLen);
