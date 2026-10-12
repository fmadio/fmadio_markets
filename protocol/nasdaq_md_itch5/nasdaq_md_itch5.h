#pragma once

//------------------------------------------------------------------------------
//
// nasdaq_md_itch5.h
//
// Nasdaq TotalView-ITCH 5.0 protocol decoder interface.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fParquet.h"
#include "fCapture.h"
#include "fProtocol.h"

// creates the flat ITCH 5.0 parquet schema and appender on the context
bool Protocol_ITCH5SchemaCreate(Parquet_t* pq);

// returns true if the UDP destination (host byte order) is a TotalView-ITCH 5.0
// multicast group + port for the Nasdaq, NTX or PSX exchanges (no endpoint
// context, the endpoint argument is unused)
bool Protocol_ITCH5PacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpoint);

// decodes one MoldUDP64 packet (UDP payload) writing every contained ITCH
// message as a row into the parquet table. returns the message count decoded
u32 Protocol_ITCH5Decode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpoint, const u8* payload, u32 payloadLen);
