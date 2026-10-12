#pragma once

//------------------------------------------------------------------------------
//
// tcpstream.h
//
// per flow TCP stream reassembly. the packet loop (main.c) feeds raw TCP
// packets in capture order; the reassembler handles SYN resets, out of order
// segments, retransmits and partial overlaps, and delivers the reassembled
// IN ORDER payload byte stream through the output callback. the callback
// (main.c) hands the stream segments to the active TCP protocol decoder.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fNetwork.h"

struct TCPStream_t;
typedef struct TCPStream_t TCPStream_t;

// delivery flags
#define TCPSTREAM_FLAG_RESET		(1 << 0)	// SYN seen: new stream, decoder framing state must reset (payload length 0)
#define TCPSTREAM_FLAG_REASSEMBLE	(1 << 1)	// payload was reassembled from out of order segments

// output callback: reassembled in order payload. user is the per call context
// handed to fTCPStream_PacketAdd; ts is the pcap timestamp of the packet that
// completed this payload
typedef void (*TCPStreamOutput_f)(void* user, u64 ts, const u8* payload, u32 length, u32 flag);

// create a stream reassembler for one flow. name is a short description used
// in diagnostic prints (copied)
TCPStream_t* fTCPStream_Init(const char* name, TCPStreamOutput_f output);

// add one TCP packet (header + payload in capture order). in order payload is
// delivered synchronously through the output callback with the given user
// context; out of order payload is buffered until the gap fills
void fTCPStream_PacketAdd(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, s32 Length, const u8* Payload, void* user);

// per stream stats
void fTCPStream_FlowStats(TCPStream_t* S, FILE* Out);

// free the stream and any buffered out of order segments
void fTCPStream_Close(TCPStream_t* S);

// global stats across every stream, for the summary
u64 fTCPStream_TotalStream(void);
u64 fTCPStream_TotalByte(void);
u64 fTCPStream_TotalPktOOO(void);
u64 fTCPStream_TotalPktDrop(void);
