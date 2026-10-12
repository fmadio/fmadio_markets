------------------------------------------------------------------------------
--
-- gen_pcap.lua
--
-- Generates a synthetic FIX 4.2 over TCP validation pcap: a full session
-- (both directions, handshake + Logon .. Logout) plus the decoder edge
-- cases: a message split across TCP segments, multiple messages packed into
-- one segment, an out of order TCP segment, a LENGTH/DATA pair with an
-- embedded SOH, a repeating group (duplicate tags), a custom tag and a tag
-- above 1024, a corrupted checksum, a mid stream capture start (resync) and
-- a non FIX TCP flow. Field values are mirrored in validate_synthetic.lua.
--
-- usage: luajit gen_pcap.lua <output.pcap>
--
------------------------------------------------------------------------------

local SOH = string.char(1)

-- big endian packers
local function be16(v)
	return string.char(math.floor(v / 256) % 256, v % 256)
end

local function be32(v)
	return be16(math.floor(v / 65536)) .. be16(v % 65536)
end

-- little endian packers (pcap file format)
local function le16(v)
	return string.char(v % 256, math.floor(v / 256) % 256)
end

local function le32(v)
	return le16(v % 65536) .. le16(math.floor(v / 65536))
end

------------------------------------------------------------------------------
-- FIX message builder: body = list of "tag=value" strings starting with 35=.
-- prepends 8=/9=, appends the computed 10= checksum (or a forced bad one)
------------------------------------------------------------------------------
local function fixMsg(body, forceChecksum)
	local b = table.concat(body, SOH) .. SOH
	local full = "8=FIX.4.2" .. SOH .. "9=" .. #b .. SOH .. b
	local sum = 0
	for i = 1, #full do
		sum = sum + full:byte(i)
	end
	local cs = forceChecksum or string.format("%03d", sum % 256)
	return full .. "10=" .. cs .. SOH
end

------------------------------------------------------------------------------
-- the session: client CLIENT1 -> server BROKER and back. sequence numbers
-- (34) and field values are asserted by validate_synthetic.lua
------------------------------------------------------------------------------

-- client -> server (inbound application flow)
local cLogon  = fixMsg({ "35=A", "34=1", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:00", "98=0", "108=30" })
local cNOS    = fixMsg({ "35=D", "34=2", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:01",
                         "11=ORD0001", "55=7203", "54=1", "38=100", "40=2", "44=1234.5", "59=0",
                         "60=20250925-01:00:01" })
local cData   = fixMsg({ "35=D", "34=3", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:02",
                         "11=ORD0002", "55=7203", "54=2", "38=50", "40=1",
                         "95=5", "96=AB" .. SOH .. "CD",
                         "60=20250925-01:00:02" })
local cGroup  = fixMsg({ "35=D", "34=4", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:03",
                         "11=ORD0003", "55=7203", "54=1", "38=10", "40=2", "44=999.25",
                         "386=2", "336=X", "336=Y",
                         "847=XYZ", "5001=FOO" })
local cCancel = fixMsg({ "35=F", "34=5", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:04",
                         "41=ORD0001", "11=ORD0004", "55=7203", "54=1" })
local cLogout = fixMsg({ "35=5", "34=6", "49=CLIENT1", "56=BROKER", "52=20250925-01:00:05" })

-- server -> client (outbound execution flow)
local sLogon  = fixMsg({ "35=A", "34=1", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:00", "98=0", "108=30" })
local sERNew  = fixMsg({ "35=8", "34=2", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:01",
                         "37=EX0001", "17=E1", "20=0", "150=0", "39=0", "11=ORD0001", "55=7203",
                         "54=1", "38=100", "44=1234.5", "32=0", "31=0", "151=100", "14=0", "6=0" })
local sERFill = fixMsg({ "35=8", "34=3", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:02",
                         "37=EX0001", "17=E2", "20=0", "150=2", "39=2", "11=ORD0001", "55=7203",
                         "54=1", "38=100", "44=1234.5", "32=100", "31=1234.5", "151=0", "14=100",
                         "6=1234.5" })
local sHeart  = fixMsg({ "35=0", "34=4", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:03" })
local sERCxl  = fixMsg({ "35=8", "34=5", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:04",
                         "37=EX0001", "17=E3", "20=0", "150=4", "39=4", "11=ORD0004", "41=ORD0001",
                         "55=7203", "54=1" })
local sBadCS  = fixMsg({ "35=3", "34=6", "49=BROKER", "56=CLIENT1", "52=20250925-01:00:05",
                         "45=99", "58=BADCHECKSUM" }, "000")

-- mid stream flow: garbage tail of a truncated message, then a complete one
local mTail   = "54=1" .. SOH .. "38=100" .. SOH .. "10=123" .. SOH
local mHeart  = fixMsg({ "35=0", "34=1", "49=CLIENT2", "56=BROKER", "52=20250925-01:00:06" })

-- non FIX flow payload
local nHTTP   = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

------------------------------------------------------------------------------
-- TCP / IPv4 / Ethernet framing
------------------------------------------------------------------------------
local FLAG_SYN = 0x02
local FLAG_ACK = 0x10
local FLAG_PSH = 0x08

local function ip4(a, b, c, d)
	return string.char(a, b, c, d)
end

local function tcpPkt(ipSrc, ipDst, portSrc, portDst, seq, ack, flags, payload)
	payload = payload or ""
	local eth = string.char(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
		.. string.char(0x02, 0x00, 0x00, 0x00, 0x00, 0x02) .. be16(0x0800)
	local ip = string.char(0x45, 0x00) .. be16(20 + 20 + #payload)
		.. be16(0) .. be16(0) .. string.char(64, 6) .. be16(0)
		.. ipSrc .. ipDst
	local tcp = be16(portSrc) .. be16(portDst) .. be32(seq) .. be32(ack)
		.. be16(0x5000 + flags) .. be16(65535) .. be16(0) .. be16(0)
	return eth .. ip .. tcp .. payload
end

local CLI  = ip4(192, 168, 1, 10)
local CLI2 = ip4(192, 168, 1, 11)
local WEB  = ip4(192, 168, 1, 12)
local SRV  = ip4(10, 0, 0, 5)

-- per direction sequence state
local cSeq = 1001				-- client ISN 1000, data from 1001
local sSeq = 5001				-- server ISN 5000, data from 5001

local function cPkt(payload, flags)
	local p = tcpPkt(CLI, SRV, 51234, 9898, cSeq, sSeq, flags or (FLAG_ACK + FLAG_PSH), payload)
	cSeq = cSeq + #payload
	return p
end

local function sPkt(payload, flags)
	local p = tcpPkt(SRV, CLI, 9898, 51234, sSeq, cSeq, flags or (FLAG_ACK + FLAG_PSH), payload)
	sSeq = sSeq + #payload
	return p
end

-- split the client NewOrderSingle mid message (partial frame accumulation)
local nosA = cNOS:sub(1, 40)
local nosB = cNOS:sub(41)

-- packets in capture order; the sequence state (cSeq/sSeq) advances as the
-- packets are built, so the out of order pair must be built in line
local pkts = {}
local function add(p)
	pkts[#pkts + 1] = p
end

-- handshake (SYN resets the decoder stream state)
add(tcpPkt(CLI, SRV, 51234, 9898, 1000, 0,    FLAG_SYN,            ""))
add(tcpPkt(SRV, CLI, 9898, 51234, 5000, 1001, FLAG_SYN + FLAG_ACK, ""))
add(tcpPkt(CLI, SRV, 51234, 9898, 1001, 5001, FLAG_ACK,            ""))

-- logons
add(cPkt(cLogon))
add(sPkt(sLogon))

-- one message split across two TCP segments
add(cPkt(nosA))
add(cPkt(nosB))

-- two messages packed into one segment
add(sPkt(sERNew .. sERFill))

-- LENGTH/DATA pair + repeating group / custom tag messages packed
add(cPkt(cData .. cGroup))

-- out of order: the heartbeat and the cancel ER are consecutive on the
-- stream, but the SECOND segment (sERCxl) is captured FIRST
local oooFirstSeq  = sSeq					-- sHeart belongs here
local oooSecondSeq = sSeq + #sHeart			-- sERCxl belongs here
add(tcpPkt(SRV, CLI, 9898, 51234, oooSecondSeq, cSeq, FLAG_ACK + FLAG_PSH, sERCxl))
add(tcpPkt(SRV, CLI, 9898, 51234, oooFirstSeq,  cSeq, FLAG_ACK + FLAG_PSH, sHeart))
sSeq = oooSecondSeq + #sERCxl

-- corrupted checksum (row must still be emitted, flagged invalid)
add(sPkt(sBadCS))

-- cancel + logout
add(cPkt(cCancel))
add(cPkt(cLogout))

-- mid stream capture start: no SYN, payload begins inside a message
add(tcpPkt(CLI2, SRV, 52000, 9898, 9000, 1, FLAG_ACK + FLAG_PSH, mTail .. mHeart))

-- non FIX TCP flow: classified (catch-all) but never frames, no rows
add(tcpPkt(WEB, SRV, 53000, 8080, 7000, 1, FLAG_ACK + FLAG_PSH, nHTTP))

------------------------------------------------------------------------------
-- pcap output: nanosecond magic
------------------------------------------------------------------------------
local outName = arg[1] or "fix42_test.pcap"
local f = assert(io.open(outName, "wb"))

f:write(le32(0xa1b23c4d), le16(2), le16(4), le32(0), le32(0), le32(65535), le32(1))

local sec = 1758762000
for i, p in ipairs(pkts) do
	f:write(le32(sec + i - 1), le32(0), le32(#p), le32(#p), p)
end
f:close()

print(string.format("wrote %s: %d tcp packets, 13 fix messages expected in the decode", outName, #pkts))
