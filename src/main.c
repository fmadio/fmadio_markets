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
#include <time.h>
#include <arpa/inet.h>

#include "fTypes.h"
#include "fParquet.h"
#include "nasdaq_md_itch5.h"
#include "opra_md_pillar6.h"

//------------------------------------------------------------------------------
// protocol selection: which decoder owns the parquet schema and receives
// classified packets. selected on the command line with -p, or autodetected
// from the first UDP packet that matches a protocol classifier (default)

typedef enum
{
	PROTOCOL_AUTO = 0,			// autodetect from packet classification (default)
	PROTOCOL_ITCH5,				// nasdaq_md_itch5
	PROTOCOL_OPRA6,				// opra_md_pillar6

} Protocol_t;

static Protocol_t s_protocol = PROTOCOL_AUTO;

//------------------------------------------------------------------------------
// output rotation: libduckdb buffers the entire table in memory until the
// COPY on close, so with -t the output is flushed and a new parquet file
// started on every rotation period boundary (pcap time). default is no
// rotation (single output file)

static const char* s_outputName = "fmadio_markets.parquet";		// -o output name (rotation inserts the window start time before the extension)
static u64 s_rotatePeriodNS = 0;		// -t rotation period in nanoseconds, 0 = no rotation
static u64 s_rotateBucket = 0;			// current rotation window index (pcap ts / period)
static bool s_rotateBucketValid = false;	// window index is valid once the first packet is seen
static u64 s_totalFile = 0;				// parquet files written

//------------------------------------------------------------------------------
// PCAP file format

#define PCAP_MAGIC_USEC		0xa1b2c3d4		// timestamps in microseconds
#define PCAP_MAGIC_NSEC		0xa1b23c4d		// timestamps in nanoseconds

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
// Protocol headers

#define ETHER_PROTO_IPV4	0x0800
#define ETHER_PROTO_VLAN	0x8100
#define ETHER_PROTO_VLAN9	0x9100
#define ETHER_PROTO_QINQ	0x88a8

#define IPV4_PROTO_TCP		6
#define IPV4_PROTO_UDP		17

typedef struct
{
	u8		dst[6];
	u8		src[6];
	u16		proto;

} __attribute__((packed)) EtherHeader_t;

typedef struct
{
	u16		tci;			// PCP / DEI / VLAN ID
	u16		proto;			// encapsulated protocol

} __attribute__((packed)) VLANHeader_t;

typedef struct
{
	u8		verLen;			// version(4) | header length in words(4)
	u8		service;
	u16		len;
	u16		ident;
	u16		frag;
	u8		ttl;
	u8		proto;
	u16		csum;
	u32		ipSrc;
	u32		ipDst;

} __attribute__((packed)) IPv4Header_t;

typedef struct
{
	u16		portSrc;
	u16		portDst;
	u32		seqNo;
	u32		ackNo;
	u16		flags;			// data offset(4) | reserved(3) | flags(9)
	u16		window;
	u16		csum;
	u16		urgent;

} __attribute__((packed)) TCPHeader_t;

typedef struct
{
	u16		portSrc;
	u16		portDst;
	u16		length;
	u16		csum;

} __attribute__((packed)) UDPHeader_t;

//------------------------------------------------------------------------------
// parquetOpen: open the in-memory duckdb instance. The protocol specific
// schema and appender are created by the protocol decoder (e.g.
// Protocol_ITCH5SchemaCreate) after this call. The output file name is only
// needed on close, when the buffered table is written out.
//------------------------------------------------------------------------------
static bool parquetOpen(Parquet_t* pq)
{
	memset(pq, 0, sizeof(Parquet_t));

	if (duckdb_open(NULL, &pq->db) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to open duckdb\n");
		return false;
	}
	if (duckdb_connect(pq->db, &pq->con) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to connect to duckdb\n");
		return false;
	}

	return true;
}

//------------------------------------------------------------------------------
// parquetClose: flush the appender and write the protocol table out as parquet
//------------------------------------------------------------------------------
static void parquetClose(Parquet_t* pq, const char* fileName)
{
	if (pq->appender)
	{
		duckdb_appender_close(pq->appender);
		duckdb_appender_destroy(&pq->appender);
	}

	// no schema was ever created (autodetect found no protocol traffic)
	if (pq->tableName == NULL)
	{
		fprintf(stderr, "parquet: no protocol detected, nothing written to [%s]\n", fileName);
		duckdb_disconnect(&pq->con);
		duckdb_close(&pq->db);
		return;
	}

	char sql[4096];
	snprintf(sql, sizeof(sql), "COPY %s TO '%s' (FORMAT PARQUET)", pq->tableName, fileName);

	duckdb_result result;
	if (duckdb_query(pq->con, sql, &result) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to write [%s]: %s\n", fileName, duckdb_result_error(&result));
	}
	else
	{
		fprintf(stderr, "parquet: wrote [%s]\n", fileName);
		s_totalFile++;
	}
	duckdb_destroy_result(&result);

	duckdb_disconnect(&pq->con);
	duckdb_close(&pq->db);
}

//------------------------------------------------------------------------------
// stats

static u64 s_totalPkt	= 0;
static u64 s_totalByte	= 0;
static u64 s_totalTCP	= 0;
static u64 s_totalUDP	= 0;
static u64 s_totalOther	= 0;

static u64 s_totalITCH5	= 0;		// UDP packets classified as TotalView-ITCH 5.0
static u64 s_totalITCH5Msg = 0;		// ITCH messages decoded into the parquet table

static u64 s_totalOPRA6	= 0;		// UDP packets classified as OPRA Pillar v6
static u64 s_totalOPRA6Msg = 0;		// OPRA messages decoded into the parquet table

static u64 s_lastPCAPTS	= 0;		// pcap timestamp (ns) of the last packet processed
static u64 s_firstPCAPTS = 0;		// pcap timestamp (ns) of the first packet processed

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
// statusPrint: one-line processing status on stderr
//------------------------------------------------------------------------------
static void statusPrint(void)
{
	fprintf(stderr, "[%s]  Pkt:%10.2f %10.3f GB tcp %8llu udp %8llu\n", 
			FormatTS(s_lastPCAPTS),
			s_totalPkt/1e6, 
			s_totalByte/1e9, 
			s_totalTCP, 
			s_totalUDP);
}

//------------------------------------------------------------------------------
// protocolSchemaCreate: create the parquet schema for the selected protocol
//------------------------------------------------------------------------------
static bool protocolSchemaCreate(Parquet_t* pq)
{
	switch (s_protocol)
	{
	case PROTOCOL_ITCH5:
		return Protocol_ITCH5SchemaCreate(pq);

	case PROTOCOL_OPRA6:
		return Protocol_OPRA6SchemaCreate(pq);

	default:
		return false;
	}
}

//------------------------------------------------------------------------------
// protocolAutoDetect: match the UDP destination against every protocol
// classifier. on the first hit the protocol is locked in for the rest of the
// run and its parquet schema is created
//------------------------------------------------------------------------------
static void protocolAutoDetect(Parquet_t* pq, u32 ipDst, u16 portDst)
{
	const char* protocolName = NULL;

	if (Protocol_ITCH5PacketClassify(ipDst, portDst))
	{
		s_protocol = PROTOCOL_ITCH5;
		protocolName = "nasdaq_md_itch5";
	}
	else
	{
		OPRA6Endpoint_t endpoint;
		if (Protocol_OPRA6PacketClassify(ipDst, portDst, &endpoint))
		{
			s_protocol = PROTOCOL_OPRA6;
			protocolName = "opra_md_pillar6";
		}
	}

	if (protocolName == NULL)
	{
		return;
	}

	fprintf(stderr, "protocol: autodetected [%s]\n", protocolName);
	if (!protocolSchemaCreate(pq))
	{
		fprintf(stderr, "protocol: failed to create [%s] parquet schema\n", protocolName);
		exit(1);
	}
}

//------------------------------------------------------------------------------
// parquetFileNameBuild: output file name for the rotation window starting at
// windowStartNS. the window start time (UTC) is inserted before the file
// extension e.g. out.parquet -> out_20230822_133000.parquet. with rotation
// disabled the -o name is used as is
//------------------------------------------------------------------------------
static const char* parquetFileNameBuild(u64 windowStartNS)
{
	if (s_rotatePeriodNS == 0)
	{
		return s_outputName;
	}

	// file extension = everything from the last '.' in the last path component
	const char* ext = strrchr(s_outputName, '.');
	if ((ext == NULL) || (strchr(ext, '/') != NULL))
	{
		ext = s_outputName + strlen(s_outputName);
	}

	static char name[4096];
	clock_date_t c = ns2clock_utc(windowStartNS);
	snprintf(name, sizeof(name), "%.*s_%04d%02d%02d_%02d%02d%02d%s", (int)(ext - s_outputName), s_outputName, c.year, c.month, c.day, c.hour, c.min, c.sec, ext);
	return name;
}

//------------------------------------------------------------------------------
// parquetRotate: flush the current rotation window out to its parquet file
// and start a new window: fresh duckdb instance + protocol schema. only
// called once a protocol has been selected (tableName != NULL)
//------------------------------------------------------------------------------
static void parquetRotate(Parquet_t* pq)
{
	parquetClose(pq, parquetFileNameBuild(s_rotateBucket * s_rotatePeriodNS));

	if (!parquetOpen(pq))
	{
		exit(1);
	}
	if (!protocolSchemaCreate(pq))
	{
		fprintf(stderr, "parquet: failed to recreate the protocol schema on rotation\n");
		exit(1);
	}
}

//------------------------------------------------------------------------------
// ProcessTCP: handle a single TCP packet
//   pq         - parquet output context
//   ts         - timestamp in nanoseconds since epoch
//   ipv4       - IPv4 header
//   tcp        - TCP header
//   payload    - start of the TCP payload
//   payloadLen - number of payload bytes
//------------------------------------------------------------------------------
static void ProcessTCP(Parquet_t* pq, u64 ts, IPv4Header_t* ipv4, TCPHeader_t* tcp, u8* payload, u32 payloadLen)
{
	s_totalTCP++;

	(void)pq;
	(void)ts;
	(void)ipv4;
	(void)tcp;
	(void)payload;
	(void)payloadLen;
}

//------------------------------------------------------------------------------
// ProcessUDP: handle a single UDP packet
//------------------------------------------------------------------------------
static void ProcessUDP(Parquet_t* pq, u64 ts, IPv4Header_t* ipv4, UDPHeader_t* udp, u8* payload, u32 payloadLen)
{
	s_totalUDP++;

	// no protocol selected yet: lock in the first classifier match
	if (s_protocol == PROTOCOL_AUTO)
	{
		protocolAutoDetect(pq, ntohl(ipv4->ipDst), ntohs(udp->portDst));
	}

	// exchange traffic is identified by multicast group + port
	switch (s_protocol)
	{
	case PROTOCOL_ITCH5:
		if (Protocol_ITCH5PacketClassify(ntohl(ipv4->ipDst), ntohs(udp->portDst)))
		{
			s_totalITCH5++;
			s_totalITCH5Msg += Protocol_ITCH5Decode(pq, ts, payload, payloadLen);
		}
		break;

	case PROTOCOL_OPRA6:
	{
		OPRA6Endpoint_t endpoint;
		if (Protocol_OPRA6PacketClassify(ntohl(ipv4->ipDst), ntohs(udp->portDst), &endpoint))
		{
			s_totalOPRA6++;
			s_totalOPRA6Msg += Protocol_OPRA6Decode(pq, ts, &endpoint, payload, payloadLen);
		}
	}
	break;

	default:
		break;
	}
}

//------------------------------------------------------------------------------
// ProcessPacket: ethernet decode, VLAN strip, TCP/UDP identification
//   pq      - parquet output context
//   ts      - timestamp in nanoseconds since epoch
//   payload - start of the ethernet frame
//   length  - captured length in bytes
//------------------------------------------------------------------------------
static void ProcessPacket(Parquet_t* pq, u64 ts, u8* payload, u32 length)
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

	EtherHeader_t* ether = (EtherHeader_t*)payload;

	u8* ptr = payload + sizeof(EtherHeader_t);
	u8* end = payload + length;
	u16 etherProto = ntohs(ether->proto);

	// strip any VLAN tags (single, double / QinQ, ...)
	while ((etherProto == ETHER_PROTO_VLAN) || (etherProto == ETHER_PROTO_VLAN9) || (etherProto == ETHER_PROTO_QINQ))
	{
		if (ptr + sizeof(VLANHeader_t) > end)
		{
			return;
		}

		VLANHeader_t* vlan = (VLANHeader_t*)ptr;
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

		ProcessTCP(pq, ts, ipv4, tcp, tcpPayload, tcpPayloadLen);
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

		ProcessUDP(pq, ts, ipv4, udp, udpPayload, udpPayloadLen);
	}
	break;

	default:
		s_totalOther++;
		break;
	}
}

//------------------------------------------------------------------------------
// usagePrint: command line help
//------------------------------------------------------------------------------
static void usagePrint(const char* progName)
{
	fprintf(stderr, "usage: %s [-r <pcap file>] [-o <parquet file>] [-p <protocol>] [-t <seconds>]\n", progName);
	fprintf(stderr, "  -r <pcap file>     read from a pcap file (default: stdin)\n");
	fprintf(stderr, "  -o <parquet file>  output parquet file (default: fmadio_markets.parquet)\n");
	fprintf(stderr, "  -t <seconds>       output rotation period in pcap time (default: no rotation)\n");
	fprintf(stderr, "                     a new file <name>_<YYYYMMDD_HHMMSS><ext> is written on\n");
	fprintf(stderr, "                     every period boundary. 0 = single file named exactly -o\n");
	fprintf(stderr, "  -p <protocol>      protocol decoder (default: auto)\n");
	fprintf(stderr, "                       auto                    : autodetect from packet classification\n");
	fprintf(stderr, "                       nasdaq_md_itch5 | itch5 : Nasdaq TotalView-ITCH 5.0\n");
	fprintf(stderr, "                       opra_md_pillar6 | opra  : OPRA Pillar Binary v6\n");
}

//------------------------------------------------------------------------------
// main: reads a PCAP from the -r file argument, or stdin when not specified
//------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio_markets - market data pcap processor https://fmad.io\n");
	fprintf(stderr, "\n");

	const char* fileName = NULL;
	for (s32 i = 1; i < argc; i++)
	{
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
				s_protocol = PROTOCOL_AUTO;
			}
			else if ((strcmp(protocolName, "nasdaq_md_itch5") == 0) || (strcmp(protocolName, "itch5") == 0))
			{
				s_protocol = PROTOCOL_ITCH5;
			}
			else if ((strcmp(protocolName, "opra_md_pillar6") == 0) || (strcmp(protocolName, "opra") == 0))
			{
				s_protocol = PROTOCOL_OPRA6;
			}
			else
			{
				fprintf(stderr, "unknown protocol [%s]\n", protocolName);
				usagePrint(argv[0]);
				return 1;
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

	// timestamp sub-second scale to nanoseconds
	u64 timeScale = 0;
	switch (header.magic)
	{
	case PCAP_MAGIC_USEC:
		timeScale = 1000;
		break;
	case PCAP_MAGIC_NSEC:
		timeScale = 1;
		break;
	default:
		fprintf(stderr, "invalid pcap magic %08x\n", header.magic);
		return 1;
	}

	u32 bufferSize = (header.snapLen > 0) ? header.snapLen : kKB(64);
	u8* buffer = malloc(bufferSize);
	if (!buffer)
	{
		fprintf(stderr, "failed to allocate %u byte packet buffer\n", bufferSize);
		return 1;
	}

	// parquet output, passed into the protocol decoders
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
	if (s_protocol != PROTOCOL_AUTO)
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
	u64 nextStatusTS = 0; 
	while (true)
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

		// output rotation on pcap time period boundaries. rotation waits for
		// a protocol to be selected (tableName set), until then only the
		// window index is tracked
		if (s_rotatePeriodNS > 0)
		{
			u64 bucket = ts / s_rotatePeriodNS;
			if (!s_rotateBucketValid)
			{
				s_rotateBucket = bucket;
				s_rotateBucketValid = true;
			}
			else if (bucket != s_rotateBucket)
			{
				if (parquet.tableName != NULL)
				{
					parquetRotate(&parquet);
				}
				s_rotateBucket = bucket;
			}
		}

		ProcessPacket(&parquet, ts, buffer, pkt.lengthCapture);


		// periodic status line: clock_gettime per packet is too slow,
		// so only check the wall clock every STATUS_CHECK_MASK+1 packets
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

	// flush the final burst window
	if (s_burstByte > s_burstMaxByte)
	{
		s_burstMaxByte = s_burstByte;
	}

	// bandwidth from pcap timestamps: bits / nanoseconds == Gbits / seconds
	u64 durationNS = s_lastPCAPTS - s_firstPCAPTS;
	double avgGbps = (durationNS > 0) ? (s_totalByte * 8.0) / durationNS : 0.0;
	double peakGbps = (s_burstMaxByte * 8.0) / BURST_WINDOW_NS;

	// flush the final rotation window. with rotation enabled but no packets
	// seen there is no window start time, fall back to the plain -o name
	if ((s_rotatePeriodNS > 0) && (s_rotateBucketValid))
	{
		parquetClose(&parquet, parquetFileNameBuild(s_rotateBucket * s_rotatePeriodNS));
	}
	else
	{
		parquetClose(&parquet, s_outputName);
	}

	fprintf(stderr, "Summary\n");
	fprintf(stderr, "  Byte     : %llu\n", s_totalByte);
	fprintf(stderr, "  Pkt      : %llu\n", s_totalPkt);
	fprintf(stderr, "  Pkt TCP  : %llu\n", s_totalTCP);
	fprintf(stderr, "  Pkt UDP  : %llu\n", s_totalUDP);
	fprintf(stderr, "  Pkt Other: %llu\n", s_totalOther);
	switch (s_protocol)
	{
	case PROTOCOL_ITCH5:
		fprintf(stderr, "  Pkt ITCH5: %llu\n", s_totalITCH5);
		fprintf(stderr, "  Msg ITCH5: %llu\n", s_totalITCH5Msg);
		break;

	case PROTOCOL_OPRA6:
		fprintf(stderr, "  Pkt OPRA6: %llu\n", s_totalOPRA6);
		fprintf(stderr, "  Msg OPRA6: %llu\n", s_totalOPRA6Msg);
		break;

	case PROTOCOL_AUTO:
		fprintf(stderr, "  Protocol : none detected\n");
		break;

	default:
		break;
	}
	fprintf(stderr, "  Files    : %llu\n", s_totalFile);
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
