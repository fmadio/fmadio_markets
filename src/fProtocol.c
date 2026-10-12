//------------------------------------------------------------------------------
//
// fProtocol.c
//
// protocol decoder registry (see fProtocol.h). registration happens in the
// protocols' constructors before main() runs; the registration order (and
// therefore autodetect priority) is the Makefile link order of the wildcard
// discovered protocol/*/*.c files.
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>

#include "fTypes.h"
#include "fProtocol.h"

static Protocol_t*	s_protocolList[PROTOCOL_MAX];
static u32			s_protocolCount = 0;

//------------------------------------------------------------------------------
// Protocol_Register: called from each protocol's constructor at program start
//------------------------------------------------------------------------------
void Protocol_Register(Protocol_t* protocol)
{
	if (s_protocolCount >= PROTOCOL_MAX)
	{
		fprintf(stderr, "protocol: registry full (%u), increase PROTOCOL_MAX\n", PROTOCOL_MAX);
		exit(1);
	}
	if (protocol->endpointSize > PROTOCOL_ENDPOINT_MAX)
	{
		fprintf(stderr, "protocol: [%s] endpoint size %u exceeds PROTOCOL_ENDPOINT_MAX\n", protocol->name, protocol->endpointSize);
		exit(1);
	}
	if ((protocol->ipProto != IPV4_PROTO_UDP) && (protocol->ipProto != IPV4_PROTO_TCP))
	{
		fprintf(stderr, "protocol: [%s] ipProto %u is not IPV4_PROTO_UDP or IPV4_PROTO_TCP\n", protocol->name, protocol->ipProto);
		exit(1);
	}

	s_protocolList[s_protocolCount++] = protocol;
}

//------------------------------------------------------------------------------
// registry access
//------------------------------------------------------------------------------
u32 protocolCount(void)
{
	return s_protocolCount;
}

Protocol_t* protocolGet(u32 i)
{
	return (i < s_protocolCount) ? s_protocolList[i] : NULL;
}
