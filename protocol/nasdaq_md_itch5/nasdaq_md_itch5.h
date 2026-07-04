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

// creates the flat ITCH 5.0 parquet schema and appender on the context
bool Protocol_ITCH5SchemaCreate(Parquet_t* pq);

// returns true if the UDP destination (host byte order) is a TotalView-ITCH 5.0
// multicast group + port for the Nasdaq, NTX or PSX exchanges
bool Protocol_ITCH5PacketClassify(u32 ipDst, u16 portDst);

// decodes one MoldUDP64 packet (UDP payload) writing every contained ITCH
// message as a row into the parquet table. returns the message count decoded
u32 Protocol_ITCH5Decode(Parquet_t* pq, u64 pcapTS, const u8* payload, u32 payloadLen);
