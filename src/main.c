//------------------------------------------------------------------------------
//
// fmadio_markets
//
// general purpose framework for generating market data and order execution 
// protcol decoders assisted using Claude 
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>

#include "fTypes.h"
#include "fParquet.h"
#include "fCapture.h"
#include "fNetwork.h"
#include "parq.h"
#include "fProtocol.h"
#include "tcpstream.h"

//---------------------------------------------------------------------------------------------

#define MARKETS_VERSION_MAJOR	1
#define MARKETS_VERSION_MINOR	6
#define MARKETS_VERSION_PATCH	0
#define MARKETS_BUILD_TIME		(__DATE__ " " __TIME__)


//------------------------------------------------------------------------------
// protocol selection: which decoder owns the parquet schema and receives
// classified packets. selected on the command line with -p, or autodetected
// from the first UDP packet that matches a protocol classifier (default)

//------------------------------------------------------------------------------
// first signal requests a clean shutdown (the main loop exits and the
// buffered parquet table is written out), second one force quits

static volatile bool s_Exit = false;

static void signalHandler(int signo)
{
	(void)signo;
	if (s_Exit)
	{
		_exit(1);								// second ctrl-c force quits
	}
	s_Exit = true;
}

//------------------------------------------------------------------------------

// the active protocol decoder from the fProtocol.h registry. selected on the
// command line with -p, or autodetected from the first UDP packet that
// matches a protocol classifier (NULL = autodetecting)
static Protocol_t* s_protocol = NULL;

//------------------------------------------------------------------------------
// output configuration, handed to parq.c (parquetConfig) after arg parsing

static const char* s_outputName = PARQUET_OUTPUT_DEFAULT;		// -o output name, handed to parquetConfig (rotation inserts the window start time before the extension)
static u64 s_rotatePeriodNS = 0;		// -t rotation period in nanoseconds, 0 = no rotation

//------------------------------------------------------------------------------
// PCAP file format

#define PCAP_MAGIC_USEC		0xa1b2c3d4		// timestamps in microseconds
#define PCAP_MAGIC_NSEC		0xa1b23c4d		// timestamps in nanoseconds
#define PCAP_MAGIC_FMAD		0x1337bab3		// FMAD chunked stream (stream_cat output)

typedef struct
{
	u32		magic;
	u16		versionMajor;
	u16		versionMinor;
	u32		timeZone;
	u32		sigFlag;
	u32		snapLen;
	u32		linkType;

} __attribute__((packed)) PCAPHeader_t;

typedef struct
{
	u32		sec;			// seconds
	u32		subSec;			// usec or nsec depending on the file magic
	u32		lengthCapture;	// bytes captured in the file
	u32		lengthWire;		// bytes on the wire

} __attribute__((packed)) PCAPPacket_t;

//------------------------------------------------------------------------------
// FMAD chunked stream format: after the PCAPHeader_t
// the stream is a sequence of FMADHeader_t chunk headers each followed by
// Length bytes holding PktCnt packets of FMADPacket_t + payload. ChunkID and
// per packet ChunkOffset address the packet on the capture device storage
// and feed the pkt_block / pkt_offset parquet columns

#define FMAD_CHUNK_MAX		kKB(256)		// chunk size fixed by the capture architecture; FMADPacket_t.chunkOffset (18 bits) spans exactly this

typedef struct
{
	u16		pktCnt;			// number of packets in this chunk
	u16		crc16;

	u32		bytesWire;		// total wire bytes
	u32		bytesCapture;	// total capture bytes
	u32		length;			// length of this chunk payload in bytes

	u64		tsStart;		// TS of first packet
	u64		tsEnd;			// TS of last packet

	u64		bytePending;	// upstream bytes pending

	u64		chunkID;		// capture side chunk id

	u16		cpuActive;		// cpu pct stream_cat is active
	u16		cpuFetch;		// cpu pct spent fetching data
	u16		cpuSend;		// cpu pct sending data
	u16		pad3;

} __attribute__((packed)) FMADHeader_t;

typedef struct
{
	u64		ts;						// 64bit nanosecond epoch

	u32		lengthCapture	: 16;	// length captured
	u32		lengthWire		: 16;	// length on the wire

	u32		portNo			:  6;	// capture port number
	u32		flag			:  8;	// flags
	u32		chunkOffset		: 18;	// physical byte offset of the packet inside the stored chunk

} __attribute__((packed)) FMADPacket_t;

//------------------------------------------------------------------------------
// stats

static u64 s_totalPkt	= 0;
static u64 s_totalByte	= 0;
static u64 s_totalTCP	= 0;
static u64 s_totalUDP	= 0;
static u64 s_totalOther	= 0;

static u64 s_lastPCAPTS	= 0;		// pcap timestamp (ns) of the last packet processed
static u64 s_firstPCAPTS = 0;		// pcap timestamp (ns) of the first packet processed

static char s_hostname[256] = "unknown";	// hostname parquet column, generated once at startup

#define STATUS_INTERVAL_NS	(10 * k1E9)		// status line print interval
#define STATUS_CHECK_MASK	0xffffULL		// check the wall clock only every 64K packets
#define BURST_WINDOW_NS		1000000ULL		// peak bandwidth burst window (1 msec)

static u64 s_burstIndex		= 0;	// current burst window index (pcap ts / BURST_WINDOW_NS)
static u64 s_burstByte		= 0;	// bytes accumulated in the current burst window
static u64 s_burstMaxByte	= 0;	// most bytes seen in any single burst window

//------------------------------------------------------------------------------
// clockRealtimeNS: current wall clock time in nanoseconds since epoch
//------------------------------------------------------------------------------
static u64 clockRealtimeNS(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (u64)ts.tv_sec * k1E9 + (u64)ts.tv_nsec;
}

//------------------------------------------------------------------------------
// statusPrint: one-line processing status on stderr. the Gbps rate is the
// pcap bytes processed since the last status line per wall clock time, i.e.
// how fast the decoder is chewing through the capture
//------------------------------------------------------------------------------
static void statusPrint(void)
{
	static u64 lastWallTS = 0;
	static u64 lastByte = 0;

	u64 wallTS = clockRealtimeNS();

	double processGbps = 0.0;
	if ((lastWallTS != 0) && (wallTS > lastWallTS))
	{
		// bits / nanoseconds == Gbits / seconds
		processGbps = ((s_totalByte - lastByte) * 8.0) / (wallTS - lastWallTS);
	}
	lastWallTS = wallTS;
	lastByte = s_totalByte;

	fprintf(stderr, "[%s]  Pkt:%10.2f %10.3f GB tcp %8llu udp %8llu : %8.3f Gbps\n",
			FormatTS(s_lastPCAPTS),
			s_totalPkt/1e6,
			s_totalByte/1e9,
			s_totalTCP,
			s_totalUDP,
			processGbps);
}

//------------------------------------------------------------------------------
// protocolSchemaCreate: create the parquet schema for the selected protocol
//------------------------------------------------------------------------------
static bool protocolSchemaCreate(Parquet_t* pq)
{
	if (s_protocol == NULL)
	{
		return false;
	}
	return s_protocol->schemaCreate(pq);
}

//------------------------------------------------------------------------------
// flow tracking: one entry per (ipSrc, ipDst, portSrc, portDst, ipProto)
// 5-tuple in an open addressing hash. the protocol classification runs ONCE
// when the flow is first seen and is cached on the entry; every subsequent
// packet of the flow dispatches straight from the cached result
//------------------------------------------------------------------------------

#define FLOW_HASH_BITS		20
#define FLOW_HASH_SIZE		(1ULL << FLOW_HASH_BITS)
#define FLOW_HASH_MASK		(FLOW_HASH_SIZE - 1)
#define FLOW_PROBE_MAX		64				// linear probe limit before falling back untracked

typedef struct
{
	// key (host byte order)
	u32			ipSrc;
	u32			ipDst;
	u16			portSrc;
	u16			portDst;
	u32			vlan;			// packed 12 bit VLAN IDs, outermost in the highest bits ((outer << 12) | inner for QinQ), 0 = untagged
	u8			ipProto;
	bool		valid;

	// classification result, cached when the flow is first seen.
	// NULL means no protocol matched this flow. endpoint holds the
	// protocol's <Protocol>Endpoint_t (protocol->endpointSize bytes)
	Protocol_t*	protocol;
	u8			endpoint[PROTOCOL_ENDPOINT_MAX];

	// tcp stream reassembler, created on the first packet of a classified
	// TCP flow (NULL for UDP flows)
	TCPStream_t*	tcpStream;

	// stats
	u64			pktCount;
	u64			byteCount;
	u64			firstTS;
	u64			lastTS;

} Flow_t;

static Flow_t	s_flowTable[FLOW_HASH_SIZE];
static u64		s_totalFlow	= 0;			// unique flows seen (table entries created)

static u32 flowHash(u32 ipSrc, u32 ipDst, u16 portSrc, u16 portDst, u32 vlan, u8 ipProto)
{
	u64 h = ((u64)ipSrc << 32) | ipDst;
	h ^= ((u64)portSrc << 48) | ((u64)portDst << 32) | ((u64)vlan << 8) | ipProto;
	h *= 0x9e3779b97f4a7c15ULL;				// 64 bit golden ratio mix
	return (u32)(h >> (64 - FLOW_HASH_BITS));
}

//------------------------------------------------------------------------------
// flowClassify: classify a new flow against the protocol classifiers, once.
// with -p auto the first flow matching any classifier locks the protocol in
// for the rest of the run and creates its parquet schema; once a protocol is
// active (via -p or locked) new flows are only matched against that protocol
//------------------------------------------------------------------------------
static void flowClassify(Parquet_t* pq, Flow_t* flow)
{
	flow->protocol = NULL;					// no protocol matched

	// a protocol is already active: classify against that protocol only.
	// the flow's transport must be the protocol's transport: a UDP protocol
	// never claims a TCP flow and vice versa
	// first cache hit optimization
	if (s_protocol != NULL)
	{
		if ((s_protocol->ipProto == flow->ipProto) && s_protocol->classify(flow->ipSrc, flow->portSrc, flow->ipDst, flow->portDst, flow->endpoint))
		{
			flow->protocol = s_protocol;
		}
		return;
	}

	// autodetect: first flow matching any registered classifier of the same
	// transport locks in the protocol for the rest of the run and creates
	// its parquet schema
	for (u32 i = 0; i < protocolCount(); i++)
	{
		Protocol_t* protocol = protocolGet(i);
		if (protocol->ipProto != flow->ipProto)
		{
			continue;
		}
		// catch-all classifiers (no well known endpoints, e.g. fix42) never
		// autodetect: they only classify when explicitly selected with -p
		if (protocol->noAutoDetect)
		{
			continue;
		}
		if (!protocol->classify(flow->ipSrc, flow->portSrc, flow->ipDst, flow->portDst, flow->endpoint))
		{
			continue;
		}

		// found the protocol
		flow->protocol = protocol;

		//fprintf(stderr, "protocol: autodetected [%s]\n", protocol->name);
		// use the local pointer, s_protocol is not set yet
		if (!protocol->schemaCreate(pq))
		{
			fprintf(stderr, "protocol: failed to create [%s] parquet schema\n", protocol->name);
			exit(1);
		}

		// first cache hit caching
		s_protocol = protocol;
		return;
	}
}

//------------------------------------------------------------------------------
// flowGet: look up the flow entry for the 5-tuple + VLAN key, creating and
// classifying it on first sight, and update the flow stats. a full flow
// table (no free slot within the probe limit) is a hard error: it means the
// capture has vastly more flows than the table was sized for and the flow
// accounting would be silently incomplete
//------------------------------------------------------------------------------
static Flow_t* flowGet(Parquet_t* pq, u32 ipSrc, u32 ipDst, u16 portSrc, u16 portDst, u32 vlan, u8 ipProto, u64 ts, u32 length)
{
	Flow_t* flow = NULL;

	u32 idx = flowHash(ipSrc, ipDst, portSrc, portDst, vlan, ipProto);
	for (u32 probe = 0; probe < FLOW_PROBE_MAX; probe++)
	{
		Flow_t* e = &s_flowTable[idx];
		if (!e->valid)
		{
			e->valid = true;
			e->ipSrc = ipSrc;
			e->ipDst = ipDst;
			e->portSrc = portSrc;
			e->portDst = portDst;
			e->vlan = vlan;
			e->ipProto = ipProto;
			flowClassify(pq, e);
			s_totalFlow++;
			flow = e;
			break;
		}
		if ((e->ipSrc == ipSrc) && (e->ipDst == ipDst) && (e->portSrc == portSrc) && (e->portDst == portDst) && (e->vlan == vlan) && (e->ipProto == ipProto))
		{
			flow = e;
			break;
		}
		idx = (idx + 1) & FLOW_HASH_MASK;
	}

	if (flow == NULL)
	{
		fprintf(stderr, "flow: table full (%llu flows, %u probe limit), increase FLOW_HASH_BITS\n", s_totalFlow, FLOW_PROBE_MAX);
		exit(1);
	}

	if (flow->pktCount == 0)
	{
		flow->firstTS = ts;
	}
	flow->pktCount++;
	flow->byteCount += length;
	flow->lastTS = ts;

	return flow;
}

//------------------------------------------------------------------------------
// footerRead: parse an arista 7130 (metamako) trailer candidate:
// seconds(4) nanoseconds(4) flags(1) deviceID(2) portID(1), all big endian.
// the position is only a candidate (trailing slack can also be padding or
// FCS), so the timestamp is sanity checked against the pcap timestamp
//------------------------------------------------------------------------------
static bool footerRead(PacketInfo_t* pkt, const u8* p)
{
	u32 sec = ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
	u32 ns  = ((u32)p[4] << 24) | ((u32)p[5] << 16) | ((u32)p[6] << 8) | (u32)p[7];

	if (ns >= k1E9)
	{
		return false;
	}

	s64 diff = (s64)sec - (s64)(pkt->pcapTS / k1E9);
	if ((diff < -5) || (diff > 5))
	{
		return false;
	}

	pkt->footerSec = sec;
	pkt->footerNS = ns;
	pkt->footerFlags = p[8];
	pkt->footerDeviceID = ((u16)p[9] << 8) | (u16)p[10];
	pkt->footerPortID = p[11];
	pkt->footerValid = true;
	return true;
}

//------------------------------------------------------------------------------
// tcpStreamDeliver: tcpstream.c output callback. receives the reassembled in
// order stream payload and hands it to the flow's TCP protocol decoder. the
// user context carries the parquet output and the delivering packet's
// capture metadata
//------------------------------------------------------------------------------
typedef struct
{
	Parquet_t*			pq;
	Flow_t*				flow;
	const PacketInfo_t*	pkt;

} TCPDeliver_t;

static void tcpStreamDeliver(void* user, u64 ts, const u8* payload, u32 length, u32 flag)
{
	TCPDeliver_t* ctx = (TCPDeliver_t*)user;
	(void)ts;

	Protocol_t* protocol = ctx->flow->protocol;

	// stream reset (SYN): forwarded as payload=NULL length=0 so the decoder
	// discards any partial framing state (see fProtocol.h)
	if (flag & TCPSTREAM_FLAG_RESET)
	{
		protocol->decode(ctx->pq, ctx->pkt, ctx->flow->endpoint, NULL, 0);
		return;
	}

	protocol->totalMsg += protocol->decode(ctx->pq, ctx->pkt, ctx->flow->endpoint, payload, length);
}

//------------------------------------------------------------------------------
// ProcessTCP: handle a single TCP packet. the protocol was identified once
// when the flow was first seen; the packet is fed through the flow's stream
// reassembler which delivers in order payload to the decoder via
// tcpStreamDeliver
//------------------------------------------------------------------------------
static void ProcessTCP(Parquet_t* pq, Flow_t* flow, const PacketInfo_t* pkt, TCPHeader_t* tcp, u8* payload, u32 payloadLen)
{
	s_totalTCP++;

	Protocol_t* protocol = flow->protocol;
	if (protocol == NULL)
	{
		// flow matched no protocol
		return;
	}

	protocol->totalPkt++;

	if (flow->tcpStream == NULL)
	{
		char name[128];
		char ipSrc[20];
		char ipDst[20];
		ip4Str(pkt->ipSrc, ipSrc);
		ip4Str(pkt->ipDst, ipDst);
		snprintf(name, sizeof(name), "%s:%u-%s:%u", ipSrc, pkt->portSrc, ipDst, pkt->portDst);

		flow->tcpStream = fTCPStream_Init(name, tcpStreamDeliver);
	}

	TCPDeliver_t ctx;
	ctx.pq = pq;
	ctx.flow = flow;
	ctx.pkt = pkt;

	fTCPStream_PacketAdd(flow->tcpStream, pkt->pcapTS, tcp, (s32)payloadLen, payload, &ctx);
}

//------------------------------------------------------------------------------
// ProcessUDP: handle a single UDP packet. the protocol was identified once
// when the flow was first seen; dispatch straight from the cached result
//------------------------------------------------------------------------------
static void ProcessUDP(Parquet_t* pq, Flow_t* flow, const PacketInfo_t* pkt, u8* payload, u32 payloadLen)
{
	s_totalUDP++;

	Protocol_t* protocol = flow->protocol;
	if (protocol == NULL)
	{
		// flow matched no protocol
		return;
	}

	protocol->totalPkt++;
	protocol->totalMsg += protocol->decode(pq, pkt, flow->endpoint, payload, payloadLen);
}

//------------------------------------------------------------------------------
// ProcessPacket: ethernet decode, VLAN strip, TCP/UDP identification
//   pq        - parquet output context
//   ts        - timestamp in nanoseconds since epoch
//   payload   - start of the ethernet frame
//   length    - captured length in bytes
//   pktBlock  - FMAD capture side chunk id (0 for plain pcap input)
//   pktOffset - physical byte offset inside the stored chunk (0 for pcap)
//------------------------------------------------------------------------------
static void ProcessPacket(Parquet_t* pq, u64 ts, u8* payload, u32 length, u64 pktBlock, u32 pktOffset)
{
	if (s_firstPCAPTS == 0)
	{
		s_firstPCAPTS = ts;
	}
	s_lastPCAPTS = ts;
	s_totalPkt++;
	s_totalByte += length;

	// peak bandwidth at 1msec burst granularity
	u64 burstIndex = ts / BURST_WINDOW_NS;
	if (burstIndex != s_burstIndex)
	{
		if (s_burstByte > s_burstMaxByte)
		{
			s_burstMaxByte = s_burstByte;
		}
		s_burstIndex = burstIndex;
		s_burstByte = 0;
	}
	s_burstByte += length;

	if (length < sizeof(EtherHeader_t))
	{
		return;
	}

	// capture layer metadata handed to the protocol decoders
	PacketInfo_t pkt;
	memset(&pkt, 0, sizeof(pkt));
	pkt.pcapTS = ts;
	pkt.vlanOuter = VLAN_NONE;
	pkt.vlanInner = VLAN_NONE;
	pkt.hostname = s_hostname;
	pkt.pktBlock = pktBlock;
	pkt.pktOffset = pktOffset;

	EtherHeader_t* ether = (EtherHeader_t*)payload;

	u8* ptr = payload + sizeof(EtherHeader_t);
	u8* end = payload + length;
	u16 etherProto = ntohs(ether->proto);

	// strip any VLAN tags (single, double / QinQ, ...) collecting the VLAN
	// IDs for the flow key, outermost tag in the highest bits, 0 = untagged
	u32 vlanID = 0;
	while ((etherProto == ETHER_PROTO_VLAN) || (etherProto == ETHER_PROTO_VLAN9) || (etherProto == ETHER_PROTO_QINQ))
	{
		if (ptr + sizeof(VLANHeader_t) > end)
		{
			return;
		}

		VLANHeader_t* vlan = (VLANHeader_t*)ptr;
		u16 vid = ntohs(vlan->tci) & 0xfff;
		vlanID = (vlanID << 12) | vid;
		if (pkt.vlanOuter == VLAN_NONE)
		{
			pkt.vlanOuter = vid;
		}
		else
		{
			pkt.vlanInner = vid;
		}
		etherProto = ntohs(vlan->proto);
		ptr += sizeof(VLANHeader_t);
	}

	// IPv4 only
	if (etherProto != ETHER_PROTO_IPV4)
	{
		s_totalOther++;
		return;
	}
	if (ptr + sizeof(IPv4Header_t) > end)
	{
		return;
	}

	IPv4Header_t* ipv4 = (IPv4Header_t*)ptr;

	u32 ipv4HdrLen = (ipv4->verLen & 0x0f) * 4;
	if (ipv4HdrLen < sizeof(IPv4Header_t))
	{
		return;
	}
	if (ptr + ipv4HdrLen > end)
	{
		return;
	}

	pkt.ipSrc = ntohl(ipv4->ipSrc);
	pkt.ipDst = ntohl(ipv4->ipDst);
	pkt.ipProto = ipv4->proto;

	// arista 7130 (metamako) trailer: sits in the slack between the end of
	// the IP datagram and the end of the frame. the 12 byte trailer is at the
	// frame end, or 4 bytes earlier when the capture retains the recalculated
	// FCS; footerRead disambiguates trailer vs padding/FCS by sanity checking
	// the trailer timestamp against the pcap timestamp
	u32 ipTotalLen = ntohs(ipv4->len);
	u8* ipEnd = ptr + ipTotalLen;
	if ((ipTotalLen >= ipv4HdrLen) && (ipEnd + 12 <= end))
	{
		if (!footerRead(&pkt, end - 12))
		{
			if (ipEnd + 16 <= end)
			{
				footerRead(&pkt, end - 16);
			}
		}
	}

	u8* ipv4Payload = ptr + ipv4HdrLen;

	switch (ipv4->proto)
	{
	case IPV4_PROTO_TCP:
	{
		if (ipv4Payload + sizeof(TCPHeader_t) > end)
		{
			return;
		}

		TCPHeader_t* tcp = (TCPHeader_t*)ipv4Payload;

		u32 tcpHdrLen = ((ntohs(tcp->flags) >> 12) & 0x0f) * 4;
		if (tcpHdrLen < sizeof(TCPHeader_t))
		{
			return;
		}
		if (ipv4Payload + tcpHdrLen > end)
		{
			return;
		}

		u8* tcpPayload = ipv4Payload + tcpHdrLen;
		u32 tcpPayloadLen = end - tcpPayload;

		// bound the payload by the IP header length: captures may append
		// bytes after the datagram (e.g. Arista 7130 timestamp trailer, FCS)
		// which must not be fed into the stream reassembly
		if (ipTotalLen >= ipv4HdrLen + tcpHdrLen)
		{
			u32 tcpDataLen = ipTotalLen - ipv4HdrLen - tcpHdrLen;
			if (tcpDataLen < tcpPayloadLen)
			{
				tcpPayloadLen = tcpDataLen;
			}
		}

		pkt.portSrc = ntohs(tcp->portSrc);
		pkt.portDst = ntohs(tcp->portDst);

		Flow_t* flow = flowGet(pq, pkt.ipSrc, pkt.ipDst, pkt.portSrc, pkt.portDst, vlanID, IPV4_PROTO_TCP, ts, length);
		ProcessTCP(pq, flow, &pkt, tcp, tcpPayload, tcpPayloadLen);
	}
	break;

	case IPV4_PROTO_UDP:
	{
		if (ipv4Payload + sizeof(UDPHeader_t) > end)
		{
			return;
		}

		UDPHeader_t* udp = (UDPHeader_t*)ipv4Payload;

		u8* udpPayload = ipv4Payload + sizeof(UDPHeader_t);
		u32 udpPayloadLen = end - udpPayload;

		// bound the payload by the UDP header length: captures may append
		// bytes after the datagram (e.g. Arista 7130 timestamp trailer, FCS)
		// which must not be parsed as protocol payload
		u32 udpDataLen = ntohs(udp->length);
		if (udpDataLen >= sizeof(UDPHeader_t))
		{
			udpDataLen -= sizeof(UDPHeader_t);
			if (udpDataLen < udpPayloadLen)
			{
				udpPayloadLen = udpDataLen;
			}
		}

		pkt.portSrc = ntohs(udp->portSrc);
		pkt.portDst = ntohs(udp->portDst);

		Flow_t* flow = flowGet(pq, pkt.ipSrc, pkt.ipDst, pkt.portSrc, pkt.portDst, vlanID, IPV4_PROTO_UDP, ts, length);
		ProcessUDP(pq, flow, &pkt, udpPayload, udpPayloadLen);
	}
	break;

	default:
		s_totalOther++;
		break;
	}
}

//------------------------------------------------------------------------------
// packetDispatch: per packet output rotation check, decode and periodic
// status line. shared by the pcap and FMAD chunked input loops
//------------------------------------------------------------------------------
static void packetDispatch(Parquet_t* pq, u64 ts, u8* frame, u32 length, u64 pktBlock, u32 pktOffset)
{
	// output rotation on pcap time period boundaries
	parquetRotateCheck(pq, ts);

	ProcessPacket(pq, ts, frame, length, pktBlock, pktOffset);

	// periodic status line: clock_gettime per packet is too slow,
	// so only check the wall clock every STATUS_CHECK_MASK+1 packets
	static u64 nextStatusTS = 0;
	if ((s_totalPkt & STATUS_CHECK_MASK) == 0)
	{
		u64 wallTS = clockRealtimeNS();
		if (wallTS >= nextStatusTS)
		{
			statusPrint();
			nextStatusTS = wallTS + STATUS_INTERVAL_NS;
		}
	}
}

//------------------------------------------------------------------------------
// usagePrint: command line help
//------------------------------------------------------------------------------
static void usagePrint(const char* progName)
{
	fprintf(stderr, "usage: %s [-r <pcap file>] [-o <parquet file>] [-p <protocol>] [-t <seconds>]\n", progName);
	fprintf(stderr, "  -r <pcap file>     read from a pcap file (default: stdin); input is pcap\n");
	fprintf(stderr, "                     (usec/nsec) or an FMAD chunked stream (stream_cat)\n");
	fprintf(stderr, "  -o <parquet file>  output parquet file (default: " PARQUET_OUTPUT_DEFAULT ")\n");
	fprintf(stderr, "  -t <seconds>       output rotation period in pcap time (default: no rotation)\n");
	fprintf(stderr, "                     a new file <name>_<YYYYMMDD_HHMMSS><ext> is written on\n");
	fprintf(stderr, "                     every period boundary. 0 = single file named exactly -o\n");
	fprintf(stderr, "  -p <protocol>      protocol decoder (default: auto)\n");
	fprintf(stderr, "                       auto : autodetect from packet classification\n");
	for (u32 i = 0; i < protocolCount(); i++)
	{
		Protocol_t* protocol = protocolGet(i);
		fprintf(stderr, "                       %s | %s : %s\n", protocol->name, protocol->shortName, protocol->description);
	}
	fprintf(stderr, "  -h | --help        print this help and exit\n");
	fprintf(stderr, "  -V | --version     print the version and exit\n");
}

//------------------------------------------------------------------------------
// main: reads a PCAP from the -r file argument, or stdin when not specified
//------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	printf("fmadio_markets public  %d.%d.%d (%s) market pcap processing (https://fmad.io)\n",
				MARKETS_VERSION_MAJOR,
				MARKETS_VERSION_MINOR,
				MARKETS_VERSION_PATCH,
				MARKETS_BUILD_TIME);

	const char* fileName = NULL;
	for (s32 i = 1; i < argc; i++)
	{

		if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0)
		{
			// already printed	
			return 0;
		}

		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			usagePrint(argv[0]);
			return 0;
		}

		if (strcmp(argv[i], "-r") == 0)
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "-r requires a file name\n");
				usagePrint(argv[0]);
				return 1;
			}
			fileName = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "-o requires a file name\n");
				usagePrint(argv[0]);
				return 1;
			}
			s_outputName = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-t") == 0)
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "-t requires a period in seconds\n");
				usagePrint(argv[0]);
				return 1;
			}
			char* endPtr = NULL;
			u64 rotateSec = strtoull(argv[i + 1], &endPtr, 10);
			if ((endPtr == argv[i + 1]) || (*endPtr != 0))
			{
				fprintf(stderr, "invalid rotation period [%s]\n", argv[i + 1]);
				usagePrint(argv[0]);
				return 1;
			}
			s_rotatePeriodNS = rotateSec * k1E9;
			i++;
		}
		else if (strcmp(argv[i], "-p") == 0)
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "-p requires a protocol name\n");
				usagePrint(argv[0]);
				return 1;
			}
			const char* protocolName = argv[i + 1];
			if (strcmp(protocolName, "auto") == 0)
			{
				s_protocol = NULL;
			}
			else
			{
				s_protocol = NULL;
				for (u32 p = 0; p < protocolCount(); p++)
				{
					Protocol_t* protocol = protocolGet(p);
					if ((strcmp(protocolName, protocol->name) == 0) || (strcmp(protocolName, protocol->shortName) == 0))
					{
						s_protocol = protocol;
						break;
					}
				}
				if (s_protocol == NULL)
				{
					fprintf(stderr, "unknown protocol [%s]\n", protocolName);
					usagePrint(argv[0]);
					return 1;
				}
			}
			i++;
		}
		else
		{
			fprintf(stderr, "unknown option [%s]\n", argv[i]);
			usagePrint(argv[0]);
			return 1;
		}
	}

	// hostname parquet column (capture device provenance)
	if (gethostname(s_hostname, sizeof(s_hostname)) != 0)
	{
		strcpy(s_hostname, "unknown");
	}
	s_hostname[sizeof(s_hostname) - 1] = 0;		// gethostname does not nul terminate on truncation

	// ctrl-c / SIGTERM exit the packet loop cleanly so the buffered parquet
	// table is still written out. no SA_RESTART so blocking stdin reads
	// return EINTR instead of resuming
	struct sigaction sigAct;
	memset(&sigAct, 0, sizeof(sigAct));
	sigAct.sa_handler = signalHandler;
	sigaction(SIGINT, &sigAct, NULL);
	sigaction(SIGTERM, &sigAct, NULL);
	signal(SIGPIPE, SIG_IGN);

	FILE* file = stdin;
	if (fileName != NULL)
	{
		file = fopen(fileName, "rb");
		if (!file)
		{
			fprintf(stderr, "failed to open pcap file [%s]\n", fileName);
			return 1;
		}
	}

	// file header
	PCAPHeader_t header;
	if (fread(&header, 1, sizeof(header), file) != sizeof(header))
	{
		fprintf(stderr, "failed to read pcap file header\n");
		return 1;
	}

	// timestamp sub-second scale to nanoseconds, or FMAD chunked stream
	bool isFMAD = false;
	u64 timeScale = 0;
	switch (header.magic)
	{
	case PCAP_MAGIC_USEC:
		timeScale = 1000;
		break;
	case PCAP_MAGIC_NSEC:
		timeScale = 1;
		break;
	case PCAP_MAGIC_FMAD:
		isFMAD = true;
		fprintf(stderr, "input: FMAD chunked stream\n");
		break;
	default:
		fprintf(stderr, "invalid pcap magic %08x\n", header.magic);
		return 1;
	}

	// pcap input: per packet buffer. FMAD input: whole chunk buffer
	u32 bufferSize = isFMAD ? FMAD_CHUNK_MAX : ((header.snapLen > 0) ? header.snapLen : kKB(64));
	u8* buffer = malloc(bufferSize);
	if (!buffer)
	{
		fprintf(stderr, "failed to allocate %u byte packet buffer\n", bufferSize);
		return 1;
	}

	// parquet output, passed into the protocol decoders
	parquetConfig(s_outputName, s_rotatePeriodNS, protocolSchemaCreate);

	Parquet_t parquet;
	if (!parquetOpen(&parquet))
	{
		return 1;
	}
	if (s_rotatePeriodNS > 0)
	{
		fprintf(stderr, "parquet: writing to [%s], new file every %llu sec\n", s_outputName, s_rotatePeriodNS / k1E9);
	}
	else
	{
		fprintf(stderr, "parquet: writing to [%s]\n", s_outputName);
	}

	// protocol specific schema. with autodetect the schema is created later,
	// on the first UDP packet that matches a protocol classifier
	if (s_protocol != NULL)
	{
		if (!protocolSchemaCreate(&parquet))
		{
			return 1;
		}
	}
	else
	{
		fprintf(stderr, "protocol: autodetecting from packet classification\n");
	}

	// per-packet loop
	if (isFMAD)
	{
		// FMAD chunked stream: FMADHeader_t + chunk payload of pktCnt packets
		// (FMADPacket_t + payload each). chunkID / chunkOffset feed the
		// pkt_block / pkt_offset parquet columns for capture side extraction
		while (!s_Exit)
		{
			FMADHeader_t chunkHdr;
			if (fread(&chunkHdr, 1, sizeof(chunkHdr), file) != sizeof(chunkHdr))
			{
				break;
			}

			if ((chunkHdr.length == 0) || (chunkHdr.length > bufferSize))
			{
				fprintf(stderr, "invalid FMAD chunk %llu: length %u pktcnt %u\n", chunkHdr.chunkID, chunkHdr.length, chunkHdr.pktCnt);
				break;
			}

			if (fread(buffer, 1, chunkHdr.length, file) != chunkHdr.length)
			{
				fprintf(stderr, "truncated FMAD chunk %llu\n", chunkHdr.chunkID);
				break;
			}

			u32 pos = 0;
			for (u32 p = 0; (p < chunkHdr.pktCnt) && !s_Exit; p++)
			{
				if (pos + sizeof(FMADPacket_t) > chunkHdr.length)
				{
					fprintf(stderr, "FMAD chunk %llu packet header overflows chunk at offset %u\n", chunkHdr.chunkID, pos);
					break;
				}

				FMADPacket_t* fpkt = (FMADPacket_t*)(buffer + pos);
				u32 lengthCapture = fpkt->lengthCapture;
				if (pos + sizeof(FMADPacket_t) + lengthCapture > chunkHdr.length)
				{
					fprintf(stderr, "FMAD chunk %llu packet payload overflows chunk at offset %u\n", chunkHdr.chunkID, pos);
					break;
				}

				packetDispatch(&parquet, fpkt->ts, buffer + pos + sizeof(FMADPacket_t), lengthCapture, chunkHdr.chunkID, fpkt->chunkOffset);
				pos += sizeof(FMADPacket_t) + lengthCapture;
			}
		}
	}
	else
	{
		// plain pcap: pkt_block / pkt_offset are 0
		while (!s_Exit)
		{
			PCAPPacket_t pkt;
			if (fread(&pkt, 1, sizeof(pkt), file) != sizeof(pkt))
			{
				break;
			}

			if ((pkt.lengthCapture == 0) || (pkt.lengthCapture > bufferSize))
			{
				fprintf(stderr, "invalid packet capture length %u\n", pkt.lengthCapture);
				break;
			}

			if (fread(buffer, 1, pkt.lengthCapture, file) != pkt.lengthCapture)
			{
				fprintf(stderr, "truncated packet payload\n");
				break;
			}

			// timestamp in nanoseconds since epoch
			u64 ts = (u64)pkt.sec * k1E9 + (u64)pkt.subSec * timeScale;

			packetDispatch(&parquet, ts, buffer, pkt.lengthCapture, 0, 0);
		}
	}

	// flush the final burst window
	if (s_burstByte > s_burstMaxByte)
	{
		s_burstMaxByte = s_burstByte;
	}

	// bandwidth from pcap timestamps: bits / nanoseconds == Gbits / seconds
	u64 durationNS = s_lastPCAPTS - s_firstPCAPTS;
	double avgGbps = (durationNS > 0) ? (s_totalByte * 8.0) / durationNS : 0.0;
	double peakGbps = (s_burstMaxByte * 8.0) / BURST_WINDOW_NS;

	// flush the final rotation window
	fprintf(stderr, "Writing PRAQ\n");
	parquetFinalClose(&parquet);

	fprintf(stderr, "Summary\n");
	fprintf(stderr, "  Byte     : %llu\n", s_totalByte);
	fprintf(stderr, "  Pkt      : %llu\n", s_totalPkt);
	fprintf(stderr, "  Pkt TCP  : %llu\n", s_totalTCP);
	fprintf(stderr, "  Pkt UDP  : %llu\n", s_totalUDP);
	fprintf(stderr, "  Pkt Other: %llu\n", s_totalOther);
	if (s_protocol != NULL)
	{
		fprintf(stderr, "  Pkt %s: %llu\n", s_protocol->statsName, s_protocol->totalPkt);
		fprintf(stderr, "  Msg %s: %llu\n", s_protocol->statsName, s_protocol->totalMsg);
	}
	else
	{
		fprintf(stderr, "  Protocol : none detected\n");
	}
	if (fTCPStream_TotalStream() > 0)
	{
		fprintf(stderr, "  TCP Strm : %llu\n", fTCPStream_TotalStream());
		fprintf(stderr, "  TCP Byte : %llu\n", fTCPStream_TotalByte());
		fprintf(stderr, "  TCP OOO  : %llu\n", fTCPStream_TotalPktOOO());
		fprintf(stderr, "  TCP Drop : %llu\n", fTCPStream_TotalPktDrop());
	}
	fprintf(stderr, "  Flows    : %llu\n", s_totalFlow);
	fprintf(stderr, "  Files    : %llu\n", parquetFileTotal());
	fprintf(stderr, "  Duration : %.6f sec\n", durationNS / 1e9);
	fprintf(stderr, "  Avg Rate : %.6f Gbps\n", avgGbps);
	fprintf(stderr, "  Peak Rate: %.6f Gbps (1msec burst)\n", peakGbps);

	free(buffer);
	if (file != stdin)
	{
		fclose(file);
	}

	return 0;
}
