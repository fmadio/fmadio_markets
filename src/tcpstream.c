//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2026 fmad engineering llc
//
// tcp stream reassembler. based on the fmad tcp stream exporter: the file
// output path is replaced with a callback into main.c (TCPStreamOutput_f)
// which hands the reassembled in order payload to the active TCP protocol
// decoder. reassembly logic: SYN resets the stream and parses options
// (window scale), in order payload is delivered immediately, out of order
// segments are buffered (up to TCP_BUFFER_MAX) and drained when the gap
// fills, partial overlaps deliver only the new bytes, captures that start
// mid stream lock onto the first data packet's sequence number.
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fTypes.h"
#include "fNetwork.h"
#include "tcpstream.h"

#define MAX_TCPSEGMENT		kMB(1)		// sanity cap on a single segment
#define TCP_BUFFER_MAX		1024		// max buffered out of order segments per stream

// one buffered out of order segment
typedef struct
{
	u64			TS;						// pcap timestamp of the segment
	u32			SeqNo;
	u32			Length;

	u8*			Payload;

} TCPBuffer_t;

typedef struct TCPStream_t
{
	u32				SeqNo;				// current/next expected tcp seq number
	bool			SeqNoValid;			// SYN seen or mid stream lock done

	u32				BufferListPos;
	TCPBuffer_t*	BufferList[TCP_BUFFER_MAX];

	u32				WindowScale;		// tcp window scaling value

	TCPStreamOutput_f	Output;			// reassembled payload callback into main.c
	void*			User;				// per call context, set for the duration of PacketAdd

	u64				LastTS;				// pcap timestamp of the last packet added

	u32				PktDrop;			// packets dropped (out of order buffer full)
	u32				PktOOO;				// packets out of order
	u32				PktTotal;			// total packets added

	char			Name[128];			// flow description for diagnostics

} TCPStream_t;

//---------------------------------------------------------------------------------------------
// global stats across every stream

static u64		s_TotalStream	= 0;	// streams created
static u64		s_TotalByte		= 0;	// reassembled payload bytes delivered
static u64		s_TotalPktOOO	= 0;	// out of order packets seen
static u64		s_TotalPktDrop	= 0;	// packets dropped (buffer full)

u64 fTCPStream_TotalStream(void)
{
	return s_TotalStream;
}

u64 fTCPStream_TotalByte(void)
{
	return s_TotalByte;
}

u64 fTCPStream_TotalPktOOO(void)
{
	return s_TotalPktOOO;
}

u64 fTCPStream_TotalPktDrop(void)
{
	return s_TotalPktDrop;
}

//---------------------------------------------------------------------------------------------

TCPStream_t* fTCPStream_Init(const char* name, TCPStreamOutput_f output)
{
	TCPStream_t* S = malloc(sizeof(TCPStream_t));
	if (!S)
	{
		fprintf(stderr, "tcpstream: failed to allocate stream\n");
		exit(1);
	}
	memset(S, 0, sizeof(TCPStream_t));

	S->WindowScale = 1;
	S->Output = output;

	strncpy(S->Name, name, sizeof(S->Name) - 1);
	S->Name[sizeof(S->Name) - 1] = 0;

	s_TotalStream++;
	return S;
}

//---------------------------------------------------------------------------------------------

void fTCPStream_Close(TCPStream_t* S)
{
	if (!S)
	{
		return;
	}

	for (u32 i = 0; i < S->BufferListPos; i++)
	{
		free(S->BufferList[i]->Payload);
		free(S->BufferList[i]);
	}

	memset(S, 0, sizeof(TCPStream_t));
	free(S);
}

//---------------------------------------------------------------------------------------------
// deliver reassembled in order payload to the callback and advance the
// expected sequence number
//---------------------------------------------------------------------------------------------
static void fTCPStream_OutputPayload(TCPStream_t* S, u64 TS, u32 Length, const u8* Payload, u32 Flag)
{
	S->SeqNo += Length;

	S->Output(S->User, TS, Payload, Length, Flag);

	s_TotalByte += Length;
}

//---------------------------------------------------------------------------------------------
// drain the out of order buffer: deliver every buffered segment that now
// aligns with (or straddles) the expected sequence number
//---------------------------------------------------------------------------------------------
static void fTCPStream_Reassembly(TCPStream_t* S, u64 TS, u32 Flag)
{
	while (true)
	{
		bool Hit = false;
		for (u32 i = 0; i < S->BufferListPos; i++)
		{
			TCPBuffer_t* Buffer = S->BufferList[i];

			s32 dSeqStart = Buffer->SeqNo - S->SeqNo;
			s32 dSeqEnd   = Buffer->SeqNo - S->SeqNo + Buffer->Length;

			// perfectly aligned start packet
			if (dSeqStart == 0)
			{
				fTCPStream_OutputPayload(S, TS, Buffer->Length, Buffer->Payload, Flag | TCPSTREAM_FLAG_REASSEMBLE);
				Hit = true;
			}
			// redundant packet fully before the current sequence number
			else if ((dSeqStart < 0) && (dSeqEnd <= 0))
			{
				Hit = true;
			}
			// partially straddled packet: starts before the current sequence
			// number but adds new bytes
			else if ((dSeqStart < 0) && (dSeqEnd > 0))
			{
				fTCPStream_OutputPayload(S, TS, dSeqEnd, Buffer->Payload - dSeqStart, Flag | TCPSTREAM_FLAG_REASSEMBLE);
				Hit = true;
			}

			// free and remove the consumed buffer
			if (Hit)
			{
				free(Buffer->Payload);
				free(Buffer);

				for (u32 j = i; j + 1 < S->BufferListPos; j++)
				{
					S->BufferList[j] = S->BufferList[j + 1];
				}
				S->BufferListPos--;
				break;
			}
		}
		if (!Hit)
		{
			break;
		}
	}
}

//---------------------------------------------------------------------------------------------
// SYN: reset the stream state and parse the tcp options (window scale)
//---------------------------------------------------------------------------------------------
static void fTCPStream_Syn(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, u32 SeqNo)
{
	S->SeqNo = SeqNo + 1;
	S->SeqNoValid = true;

	// release all reassembly buffers, this is a new tcp stream
	for (u32 i = 0; i < S->BufferListPos; i++)
	{
		free(S->BufferList[i]->Payload);
		free(S->BufferList[i]);
	}
	S->BufferListPos = 0;

	// parse options: kind(1) length(1) data walk
	s32 OLen = (s32)TCP_HEADER_LEN(TCP->flags) - (s32)sizeof(TCPHeader_t);
	u8* Option = (u8*)(TCP + 1);
	s32 o = 0;
	while (o < OLen)
	{
		u32 Kind = Option[o];
		if (Kind == 0)						// end of options
		{
			break;
		}
		if (Kind == 1)						// nop
		{
			o++;
			continue;
		}
		if (o + 1 >= OLen)					// truncated option
		{
			break;
		}
		u32 Len = Option[o + 1];
		if ((Len < 2) || (o + (s32)Len > OLen))
		{
			break;
		}

		// window scale
		if ((Kind == 3) && (Len == 3))
		{
			S->WindowScale = 1 << Option[o + 2];
		}
		o += Len;
	}

	// notify the decoder that its framing state must reset
	S->Output(S->User, TS, NULL, 0, TCPSTREAM_FLAG_RESET);
}

//---------------------------------------------------------------------------------------------

void fTCPStream_PacketAdd(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, s32 Length, const u8* Payload, void* user)
{
	// if length is invalid then drop the packet
	if (Length < 0)
	{
		fprintf(stderr, "tcpstream: [%s] negative payload length %i\n", S->Name, Length);
		return;
	}

	S->User = user;
	S->LastTS = TS;
	S->PktTotal++;

	u32 SeqNo = swap32(TCP->seqNo);

	if (TCP_FLAG_SYN(TCP->flags))
	{
		fTCPStream_Syn(S, TS, TCP, SeqNo);
	}

	if (Length == 0)
	{
		// ack / control only
		return;
	}

	// capture started mid stream: lock onto the first data packet
	if (!S->SeqNoValid)
	{
		S->SeqNo = SeqNo;
		S->SeqNoValid = true;
	}

	s32 dSeqNo = SeqNo - S->SeqNo;
	if (dSeqNo == 0)
	{
		// in order: deliver immediately, then drain any buffered segments
		fTCPStream_OutputPayload(S, TS, Length, Payload, 0);
		if (S->BufferListPos > 0)
		{
			fTCPStream_Reassembly(S, TS, 0);
		}
	}
	else
	{
		S->PktOOO++;
		s_TotalPktOOO++;

		// unaligned retransmit that still adds new bytes close to the
		// current sequence number: deliver only the new tail
		s32 dRemain = (SeqNo + Length) - S->SeqNo;
		if ((dSeqNo < 0) && (dRemain > 0) && (dRemain < (s32)kKB(8)))
		{
			s32 PayloadOffset = S->SeqNo - SeqNo;
			fTCPStream_OutputPayload(S, TS, dRemain, Payload + PayloadOffset, TCPSTREAM_FLAG_REASSEMBLE);
			fTCPStream_Reassembly(S, TS, 0);
		}
		// fully redundant retransmit: drop
		else if (dRemain <= 0)
		{
		}
		// gap: buffer the segment until the gap fills
		else if (S->BufferListPos < TCP_BUFFER_MAX)
		{
			if (Length >= (s32)MAX_TCPSEGMENT)
			{
				fprintf(stderr, "tcpstream: [%s] segment length overflow %i\n", S->Name, Length);
				return;
			}

			TCPBuffer_t* B = malloc(sizeof(TCPBuffer_t));
			u8* P = malloc(Length);
			if (!B || !P)
			{
				fprintf(stderr, "tcpstream: [%s] failed to allocate %i byte segment buffer\n", S->Name, Length);
				exit(1);
			}
			B->TS = TS;
			B->SeqNo = SeqNo;
			B->Length = Length;
			B->Payload = P;
			memcpy(B->Payload, Payload, Length);

			S->BufferList[S->BufferListPos++] = B;
		}
		else
		{
			// no space for reassembly so drop it
			S->PktDrop++;
			s_TotalPktDrop++;
		}
	}

	S->User = NULL;
}

//---------------------------------------------------------------------------------------------
// print per flow stats
//---------------------------------------------------------------------------------------------
void fTCPStream_FlowStats(TCPStream_t* S, FILE* Out)
{
	if (!S)
	{
		return;
	}

	fprintf(Out, " [%s] BufPos:%8u PktTotal:%8u PktOOO:%8u PktDrop:%8u",
			S->Name,
			S->BufferListPos,
			S->PktTotal,
			S->PktOOO,
			S->PktDrop);
}
