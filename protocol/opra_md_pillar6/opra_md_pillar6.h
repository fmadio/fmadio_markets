#pragma once

//------------------------------------------------------------------------------
//
// opra_md_pillar6.h
//
// OPRA Pillar Binary v6 protocol decoder interface.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fParquet.h"

// classification result: which OPRA line / stream / feed the UDP destination is
typedef struct
{
	u16		lineNumber;		// OPRA line: 1-96, 220-225 (series mapping/reserved), 201-204 (GTH)
	char	feedStream;		// 'A' or 'B' redundant multicast stream
	char	feedType;		// 'P' production, 'R' retransmission, 'T' playback test

} OPRA6Endpoint_t;

// creates the flat OPRA parquet schema and appender on the context
bool Protocol_OPRA6SchemaCreate(Parquet_t* pq);

// returns true if the UDP destination (host byte order) is an OPRA multicast
// group + port, filling in the endpoint description
bool Protocol_OPRA6PacketClassify(u32 ipDst, u16 portDst, OPRA6Endpoint_t* endpoint);

// decodes one OPRA transmission block (UDP payload) writing every contained
// message as a row into the parquet table. returns the message count decoded
u32 Protocol_OPRA6Decode(Parquet_t* pq, u64 pcapTS, const OPRA6Endpoint_t* endpoint, const u8* payload, u32 payloadLen);
