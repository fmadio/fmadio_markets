------------------------------------------------------------------------------
--
-- gen_pcap.lua
--
-- Generates a synthetic TotalView-ITCH 5.0 validation pcap containing every
-- message type (23 total) with known field values, wrapped in MoldUDP64
-- packets (including multi-message packets and a heartbeat) addressed to the
-- Nasdaq New York "A" endpoint 233.54.12.111:26477.
--
-- usage: luajit gen_pcap.lua <output.pcap>
--
------------------------------------------------------------------------------

-- big endian packers (pure arithmetic, safe above 32 bits)
local function be16(v)
	return string.char(math.floor(v / 256) % 256, v % 256)
end

local function be32(v)
	return be16(math.floor(v / 65536)) .. be16(v % 65536)
end

local function be48(v)
	return be16(math.floor(v / 2^32)) .. be32(v % 2^32)
end

local function be64(v)
	return be32(math.floor(v / 2^32)) .. be32(v % 2^32)
end

-- little endian packers (pcap file format)
local function le16(v)
	return string.char(v % 256, math.floor(v / 256) % 256)
end

local function le32(v)
	return le16(v % 65536) .. le16(math.floor(v / 65536))
end

-- alpha field: left justified, right padded with spaces
local function alpha(s, n)
	return s .. string.rep(" ", n - #s)
end

-- ITCH common header: type(1) locate(2) tracking(2) timestamp(6)
local TS = 34200000000000            -- 09:30:00 ET in ns since midnight

local function hdr(mtype, locate, track)
	return mtype .. be16(locate) .. be16(track) .. be48(TS)
end

------------------------------------------------------------------------------
-- one message of every type, values mirrored in validate.lua
------------------------------------------------------------------------------
local msgs =
{
	hdr("S", 0, 1) .. "Q",                                                     -- System Event: market open

	hdr("R", 42, 2) .. alpha("AAPL", 8) .. "Q" .. "N" .. be32(100)             -- Stock Directory
		.. "N" .. "C" .. "  " .. "P" .. "N" .. "N" .. "1" .. "N"
		.. be32(1) .. "N",

	hdr("H", 42, 3) .. alpha("AAPL", 8) .. "T" .. " " .. "    ",               -- Trading Action: trading

	hdr("Y", 42, 4) .. alpha("AAPL", 8) .. "0",                                -- Reg SHO: no price test

	hdr("L", 42, 5) .. "NSDQ" .. alpha("AAPL", 8) .. "Y" .. "N" .. "A",        -- Market Participant Position

	hdr("V", 0, 6) .. be64(190 * 1e8) .. be64(180 * 1e8) .. be64(165 * 1e8),   -- MWCB levels 190/180/165

	hdr("W", 0, 7) .. "1",                                                     -- MWCB breach level 1

	hdr("K", 42, 8) .. alpha("NEWCO", 8) .. be32(34200) .. "A" .. be32(250000),-- IPO quote 25.0000

	hdr("J", 42, 9) .. alpha("AAPL", 8) .. be32(1500000) .. be32(1650000)      -- LULD collar 150/165/135
		.. be32(1350000) .. be32(0),

	hdr("h", 42, 10) .. alpha("AAPL", 8) .. "Q" .. "T",                        -- Operational halt lifted

	hdr("A", 42, 11) .. be64(1001) .. "B" .. be32(100)                         -- Add: buy 100 AAPL @ 150.1234
		.. alpha("AAPL", 8) .. be32(1501234),

	hdr("F", 42, 12) .. be64(1002) .. "S" .. be32(200)                         -- Add MPID: sell 200 @ 150.9999
		.. alpha("AAPL", 8) .. be32(1509999) .. "JPMS",

	hdr("E", 42, 13) .. be64(1001) .. be32(50) .. be64(900001),                -- Executed: 50 of order 1001

	hdr("C", 42, 14) .. be64(1001) .. be32(25) .. be64(900002)                 -- Executed w/ price 150.1000
		.. "Y" .. be32(1501000),

	hdr("X", 42, 15) .. be64(1002) .. be32(75),                                -- Cancel 75 of order 1002

	hdr("D", 42, 16) .. be64(1002),                                            -- Delete order 1002

	hdr("U", 42, 17) .. be64(1001) .. be64(1003) .. be32(25) .. be32(1502000), -- Replace 1001 -> 1003

	hdr("P", 42, 18) .. be64(0) .. "B" .. be32(300)                            -- Hidden trade 300 @ 150.0000
		.. alpha("AAPL", 8) .. be32(1500000) .. be64(900003),

	hdr("Q", 42, 19) .. be64(50000) .. alpha("AAPL", 8)                        -- Opening cross 50000 @ 150.5000
		.. be32(1505000) .. be64(900004) .. "O",

	hdr("B", 42, 20) .. be64(900002),                                          -- Broken trade

	hdr("I", 42, 21) .. be64(10000) .. be64(500) .. "B" .. alpha("AAPL", 8)    -- NOII
		.. be32(1504000) .. be32(1505000) .. be32(1505000) .. "O" .. "L",

	hdr("N", 42, 22) .. alpha("AAPL", 8) .. "A",                               -- RPII both sides

	hdr("O", 42, 23) .. alpha("NEWCO", 8) .. "Y"                               -- DLCR
		.. be32(200000) .. be32(450000) .. be32(300000) .. be64(TS)
		.. be32(270000) .. be32(330000),
}

-- spec lengths, cross checked before writing
local expectLen =
{
	S = 12, R = 39, H = 25, Y = 20, L = 26, V = 35, W = 12, K = 28, J = 35,
	h = 21, A = 36, F = 40, E = 31, C = 36, X = 23, D = 19, U = 35, P = 44,
	Q = 40, B = 19, I = 50, N = 20, O = 48,
}

for i, m in ipairs(msgs) do
	local t = m:sub(1, 1)
	assert(#m == expectLen[t], string.format("msg %s: built %d expected %d", t, #m, expectLen[t]))
end

------------------------------------------------------------------------------
-- MoldUDP64 / UDP / IPv4 / Ethernet framing
------------------------------------------------------------------------------
local function mold(session, seq, list)
	local p = alpha(session, 10) .. be64(seq) .. be16(#list)
	for _, m in ipairs(list) do
		p = p .. be16(#m) .. m
	end
	return p
end

local function moldHeartbeat(session, seq)
	return alpha(session, 10) .. be64(seq) .. be16(0)
end

local function udpPkt(payload)
	local eth = string.char(0x01, 0x00, 0x5e, 0x36, 0x0c, 0x6f)
		.. string.char(0x02, 0x00, 0x00, 0x00, 0x00, 0x02) .. be16(0x0800)
	local ip = string.char(0x45, 0x00) .. be16(20 + 8 + #payload)
		.. be16(0) .. be16(0) .. string.char(32, 17) .. be16(0)
		.. string.char(206, 200, 127, 130)                    -- src
		.. string.char(233, 54, 12, 111)                      -- dst: Nasdaq NY A
	local udp = be16(40000) .. be16(26477) .. be16(8 + #payload) .. be16(0)
	return eth .. ip .. udp .. payload
end

local pkts =
{
	udpPkt(mold("TEST0001", 1, { unpack(msgs, 1, 12) })),     -- msgs 1..12, seq 1..12
	udpPkt(mold("TEST0001", 13, { unpack(msgs, 13, 23) })),   -- msgs 13..23, seq 13..23
	udpPkt(moldHeartbeat("TEST0001", 24)),                    -- heartbeat, no messages
}

------------------------------------------------------------------------------
-- pcap output: nanosecond magic
------------------------------------------------------------------------------
local outName = arg[1] or "itch5_test.pcap"
local f = assert(io.open(outName, "wb"))

f:write(le32(0xa1b23c4d), le16(2), le16(4), le32(0), le32(0), le32(65535), le32(1))

local sec = 1751600000
for i, p in ipairs(pkts) do
	f:write(le32(sec + i - 1), le32(0), le32(#p), le32(#p), p)
end
f:close()

print(string.format("wrote %s: %d mold packets, %d itch messages", outName, #pkts, #msgs))
