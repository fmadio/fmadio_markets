#pragma once

//------------------------------------------------------------------------------
//
// fProtocol.h
//
// protocol decoder registry. each protocol self registers at program start
// (constructor in its .c file), so main.c and the Makefile carry NO per
// protocol knowledge: adding or removing a protocol - including confidential
// ones that cannot be listed in shared source - is done purely by adding or
// removing its directory under protocol/. the Makefile picks up every
// protocol/*/*.c by wildcard.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fNetwork.h"
#include "fParquet.h"
#include "fCapture.h"

#define PROTOCOL_MAX			16		// registry capacity
#define PROTOCOL_ENDPOINT_MAX	64		// max sizeof(<Protocol>Endpoint_t) stored per flow

typedef struct Protocol_t
{
	const char*	name;			// -p canonical name (the protocol directory name)
	const char*	shortName;		// -p short alias
	const char*	statsName;		// summary line label (Pkt <statsName> / Msg <statsName>)
	const char*	description;	// usage help text
	u32			endpointSize;	// sizeof the protocol endpoint struct (0 = none), <= PROTOCOL_ENDPOINT_MAX
	u8			ipProto;		// transport the protocol runs on: IPV4_PROTO_UDP (decode() receives
								// one datagram per call) or IPV4_PROTO_TCP (decode() receives
								// reassembled in order stream segments from src/tcpstream.c).
								// validated at registration, a flow only classifies against
								// protocols of its own transport
	bool		noAutoDetect;	// the protocol has no well known endpoints and its classifier is
								// a catch-all (e.g. fix42): skipped by -p auto autodetection, it
								// only classifies flows when explicitly selected with -p

	// creates the protocol parquet schema + appender on the context
	bool	(*schemaCreate)(Parquet_t* pq);

	// returns true if the flow (host byte order 4-tuple) belongs to this
	// protocol, filling the endpoint context (endpointSize bytes). UDP
	// protocols typically match the destination (multicast group + port);
	// TCP protocols must check BOTH sides, the server is the source on the
	// server -> client flow
	bool	(*classify)(u32 ipSrc, u16 portSrc, u32 ipDst, u16 portDst, void* endpoint);

	// decodes one payload writing every contained message as a row into the
	// parquet table. returns the message count decoded. UDP protocols
	// receive one datagram per call; TCP protocols receive reassembled in
	// order stream segments plus payload=NULL length=0 on a stream reset
	// (new SYN), on which any framing state must be discarded. the endpoint
	// is writable: TCP protocols keep their per flow stream state in it
	u32		(*decode)(Parquet_t* pq, const PacketInfo_t* pkt, void* endpoint, const u8* payload, u32 payloadLen);

	// stats, updated by the packet loop
	u64		totalPkt;			// UDP packets classified as this protocol
	u64		totalMsg;			// messages decoded into the parquet table

} Protocol_t;

// called from each protocol's __attribute__((constructor)) at program start
void Protocol_Register(Protocol_t* protocol);

// registry access
u32 protocolCount(void);
Protocol_t* protocolGet(u32 i);
