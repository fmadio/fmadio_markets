#pragma once

//------------------------------------------------------------------------------
//
// efilatency.h
//
// EFI latency test packet protocol decoder interface.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fParquet.h"
#include "fCapture.h"
#include "fProtocol.h"

// creates the flat efilatency parquet schema and appender on the context
bool Protocol_EFILATSchemaCreate(Parquet_t* pq);

// returns true if the UDP flow (host byte order) is an efilatency test flow:
// source AND destination port 8080 (no well known group/subnet, see
// efilatency.md section 8; no endpoint context, the endpoint argument is
// unused)
bool Protocol_EFILATPacketClassify(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpoint);

// decodes one efilatency datagram (fixed 64 byte UDP payload: u64 BE seqNo +
// 1 byte ASCII indicator + zero padding) writing one row into the parquet
// table. returns the message count decoded (0 or 1)
u32 Protocol_EFILATDecode(Parquet_t* pq, const PacketInfo_t* pkt, void* endpoint, const u8* payload, u32 payloadLen);
