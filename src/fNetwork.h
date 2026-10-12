#pragma once

//------------------------------------------------------------------------------
//
// fNetwork.h
//
// on the wire protocol headers (ethernet / vlan / ipv4 / tcp / udp) shared
// by the packet loop (main.c) and the tcp stream reassembler (tcpstream.c).
//
//------------------------------------------------------------------------------

#include "fTypes.h"

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
	u16		flags;			// data offset(4) | reserved(3) | flags(9), network order
	u16		window;
	u16		csum;
	u16		urgent;

} __attribute__((packed)) TCPHeader_t;

// tcp flag helpers on the network order TCPHeader_t.flags field
#define TCP_FLAG_FIN(f)		((swap16(f) >> 0) & 1)
#define TCP_FLAG_SYN(f)		((swap16(f) >> 1) & 1)
#define TCP_FLAG_RST(f)		((swap16(f) >> 2) & 1)
#define TCP_FLAG_PSH(f)		((swap16(f) >> 3) & 1)
#define TCP_FLAG_ACK(f)		((swap16(f) >> 4) & 1)

// tcp header length in bytes from the data offset field
#define TCP_HEADER_LEN(f)	(((swap16(f) >> 12) & 0x0f) * 4)

typedef struct
{
	u16		portSrc;
	u16		portDst;
	u16		length;
	u16		csum;

} __attribute__((packed)) UDPHeader_t;
