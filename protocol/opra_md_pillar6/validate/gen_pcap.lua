------------------------------------------------------------------------------
--
-- gen_pcap.lua
--
-- Generates a synthetic OPRA Pillar Binary v6 validation pcap containing every
-- message category (a d f k q C H R Y) with known field values, wrapped in
-- OPRA transmission blocks. Coverage includes:
--
--   - every BBO appendage variant: none, single best bid, single best offer,
--     double (on both long and short quotes)
--   - denominator codes A B C D E H I plus the short quote implied A/B
--   - call and put expiration month codes, signed negative net change
--   - multi message blocks with implicit sequence numbering
--   - block pad byte (odd length control and admin blocks)
--   - production / retransmission / playback groups, A and B streams,
--     GTH lines with session indicators 2 and 'X', retransmitted blocks
--   - negative cases: wrong port, CTS/CQS lookalike group, wrong block
--     version, wrong data feed indicator, unknown message category mid block
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

-- zero fill (reserved fields)
local function z(n)
	return string.rep(string.char(0), n)
end

-- message header: participant(1) category(1) type(1) indicator(1)
--                 transactionId(4) participantRefNo(4)
local function hdr(part, cat, mtype, ind, transId, prn)
	return part .. cat .. mtype .. ind .. be32(transId) .. be32(prn)
end

-- expiration block: month code(1) day(1) year(1)
local function exp3(m, d, y)
	return m .. string.char(d, y)
end

------------------------------------------------------------------------------
-- transmission block: 21 byte header + messages + optional pad byte.
-- opts: sessionInd (default 0), retrans (default ' '), version (default 6),
--       feed (default 'O'), msgCount (default #msgs, for negative tests)
------------------------------------------------------------------------------
local function block(seqNo, tsSec, tsNS, msgs, opts)
	opts = opts or {}
	local sessionInd = opts.sessionInd or 0
	local retrans    = opts.retrans or " "
	local version    = opts.version or 6
	local feed       = opts.feed or "O"
	local msgCount   = opts.msgCount or #msgs

	local data = table.concat(msgs)
	local size = 21 + #data
	local pad = ""
	if size % 2 == 1 then
		pad = string.char(0)
		size = size + 1
	end

	local pre = string.char(version) .. be16(size) .. feed .. retrans
		.. string.char(sessionInd) .. be32(seqNo) .. string.char(msgCount)
		.. be32(tsSec) .. be32(tsNS)

	-- checksum: lower 16 bits of the 32 bit byte sum, excluding the checksum field
	local sum = 0
	local body = pre .. data .. pad
	for i = 1, #body do
		sum = sum + body:byte(i)
	end

	return pre .. be16(sum % 65536) .. data .. pad
end

local function udpPkt(dstIP, dstPort, payload)
	local eth = string.char(0x01, 0x00, 0x5e, dstIP[2] % 128, dstIP[3], dstIP[4])
		.. string.char(0x02, 0x00, 0x00, 0x00, 0x00, 0x02) .. be16(0x0800)
	local ip = string.char(0x45, 0x00) .. be16(20 + 8 + #payload)
		.. be16(0) .. be16(0) .. string.char(32, 17) .. be16(0)
		.. string.char(162, 69, 44, 10)                        -- src: OPRA A1 subnet
		.. string.char(dstIP[1], dstIP[2], dstIP[3], dstIP[4])
	local udp = be16(40000) .. be16(dstPort) .. be16(8 + #payload) .. be16(0)
	return eth .. ip .. udp .. payload
end

------------------------------------------------------------------------------
-- messages, values mirrored in validate_synthetic.lua
------------------------------------------------------------------------------

-- a: AAPL Aug(call) 18 2023 strike B 195.50, AUTO trade 25 @ 3.42,
--    extended session, transactionId 0x11223344, prn 7
local msgA1 = hdr("C", "a", "I", " ", 0x11223344, 7)
	.. alpha("AAPL", 5) .. z(1) .. exp3("H", 18, 23)
	.. "B" .. be32(19550) .. be32(25) .. "B" .. be32(342)
	.. be32(0) .. string.char(1) .. z(3)

-- a: MSFT Jan(call) 2 2026 strike I 425, floor trade (lower case 'e') 3 @ 9.1
local msgA2 = hdr("Q", "a", "e", " ", 0, 0)
	.. alpha("MSFT", 5) .. z(1) .. exp3("A", 2, 26)
	.. "I" .. be32(425) .. be32(3) .. "A" .. be32(91)
	.. be32(0) .. string.char(0) .. z(3)

-- k: SPY Aug(put) 18 2023 strike A 445.0, bid 3.41x10 offer 3.44x12,
--    indicator O = double appendage (best bid N 3.42x5, best offer Q 3.43x6)
local msgK1 = hdr("N", "k", " ", "O", 0, 0)
	.. alpha("SPY", 5) .. z(1) .. exp3("T", 18, 23)
	.. "A" .. be32(4450) .. "B" .. be32(341) .. be32(10) .. be32(344) .. be32(12)
	.. "N" .. "B" .. be32(342) .. be32(5)
	.. "Q" .. "B" .. be32(343) .. be32(6)

-- k: XSP Dec(put) 19 2025 strike C 5500.0, prem denom D bid 1.2345x100
--    offer 2.3456x50, indicator M = single best bid appendage (C 1.2x9)
local msgK2 = hdr("W", "k", " ", "M", 0, 0)
	.. alpha("XSP", 5) .. z(1) .. exp3("X", 19, 25)
	.. "C" .. be32(5500000) .. "D" .. be32(12345) .. be32(100) .. be32(23456) .. be32(50)
	.. "C" .. "D" .. be32(12000) .. be32(9)

-- k: TSLA Jun(call) 20 2025 strike B 300.0, bid 5.00x5 offer 5.10x6,
--    indicator F = quote is itself the BBO, no appendage
local msgK3 = hdr("T", "k", " ", "F", 0, 0)
	.. alpha("TSLA", 5) .. z(1) .. exp3("F", 20, 25)
	.. "B" .. be32(30000) .. "B" .. be32(500) .. be32(5) .. be32(510) .. be32(6)

-- q: IWM Mar(call) 15 2024 strike 225.5 (implied A), bid 1.23x4 offer 1.25x9
--    (implied B), indicator C = single best offer appendage (Z 1.24x3)
local msgQ1 = hdr("X", "q", " ", "C", 0, 0)
	.. alpha("IWM", 4) .. exp3("C", 15, 24)
	.. be16(2255) .. be16(123) .. be16(4) .. be16(125) .. be16(9)
	.. "Z" .. "B" .. be32(124) .. be32(3)

-- q: RUT Nov(put) 21 2025 strike 1900.0, zero quote (cancel), no appendage
local msgQ2 = hdr("B", "q", " ", " ", 0, 0)
	.. alpha("RUT", 4) .. exp3("W", 21, 25)
	.. be16(19000) .. be16(0) .. be16(0) .. be16(0) .. be16(0)

-- q: QQQ Jun(put) 21 2024 strike 480.0, bid 2.00x1 offer 2.10x2, indicator A
local msgQG = hdr("C", "q", " ", "A", 0, 0)
	.. alpha("QQQ", 4) .. exp3("R", 21, 24)
	.. be16(4800) .. be16(200) .. be16(1) .. be16(210) .. be16(2)

-- H: line integrity / start of day (message header only)
local msgHN = hdr("O", "H", "N", " ", 0, 0)
local msgHC = hdr("O", "H", "C", " ", 0, 0)

-- Y: SPX index based on last sale, denom A, 4456.7
local msgY1 = hdr("O", "Y", " ", " ", 0, 0)
	.. alpha("SPX", 5) .. z(1) .. "A" .. be32(44567) .. z(4)

-- Y: NDX index based on bid and offer, denom B, 16500.55 / 16501.23
local msgY2 = hdr("O", "Y", "I", " ", 0, 0)
	.. alpha("NDX", 5) .. z(1) .. "B" .. be32(1650055) .. be32(1650123)

-- d: AAPL Aug(call) 18 2023 strike B 195.50, open interest 5000
local msgD1 = hdr("M", "d", " ", " ", 0, 0)
	.. alpha("AAPL", 5) .. z(1) .. exp3("H", 18, 23)
	.. "B" .. be32(19550) .. be32(5000)

-- f: AAPL EOD summary: vol 1234 oi 5678, o/h/l/c 3.40/3.50/3.30/3.45,
--    net change -0.05 (signed 2's complement), underlying denom H (8 byte,
--    8 decimal places) 195.5, bid 3.44 offer 3.46
local msgF1 = hdr("C", "f", " ", " ", 0, 0)
	.. alpha("AAPL", 5) .. z(1) .. exp3("H", 18, 23)
	.. "B" .. be32(19550) .. be32(1234) .. be32(5678)
	.. "B" .. be32(340) .. be32(350) .. be32(330) .. be32(345)
	.. be32(2^32 - 5)
	.. "H" .. be64(19550000000)
	.. be32(344) .. be32(346)

-- C: admin text, and an admin with zero length data
local msgC1 = hdr("O", "C", " ", " ", 0, 0) .. be16(10) .. "HELLO OPRA"
local msgC2 = hdr("O", "C", " ", " ", 0, 0) .. be16(0)

-- R: TSLA Jan(call) 19 2024 strike I 250 -> line 37
local msgR1 = hdr("O", "R", "A", " ", 0, 0)
	.. alpha("TSLA", 5) .. exp3("A", 19, 24)
	.. "I" .. be32(250) .. be16(37) .. z(128)

-- R: SPY Oct(put) 17 2025 strike E 450.0 -> line 96
local msgR2 = hdr("O", "R", "A", " ", 0, 0)
	.. alpha("SPY", 5) .. exp3("V", 17, 25)
	.. "E" .. be32(45000000) .. be16(96) .. z(128)

-- unknown message category 'z': the decoder must decode nothing after it
local msgZZ = hdr("O", "z", " ", " ", 0, 0) .. z(8)

-- spec lengths, cross checked before writing
local expect =
{
	{ msgA1, 43 }, { msgA2, 43 }, { msgK1, 63 }, { msgK2, 53 }, { msgK3, 43 },
	{ msgQ1, 39 }, { msgQ2, 29 }, { msgQG, 29 }, { msgHN, 12 }, { msgHC, 12 },
	{ msgY1, 27 }, { msgY2, 27 }, { msgD1, 30 }, { msgF1, 72 }, { msgC1, 24 },
	{ msgC2, 14 }, { msgR1, 155 }, { msgR2, 155 },
}
for i, e in ipairs(expect) do
	assert(#e[1] == e[2], string.format("msg %d: built %d expected %d", i, #e[1], e[2]))
end

------------------------------------------------------------------------------
-- packets
------------------------------------------------------------------------------
local tsSec = 1692700000
local tsNS  = 123456789

local pkts =
{
	-- 1: line 14 production A: a + k + q, seq 1000..1002
	udpPkt({224,0,204,14}, 45014, block(1000, tsSec, tsNS,     { msgA1, msgK1, msgQ1 })),
	-- 2: line 14 production A: line integrity, seq = last transmitted (odd block, pad byte)
	udpPkt({224,0,204,14}, 45014, block(1002, tsSec, tsNS + 1, { msgHN })),
	-- 3: line 14 production A: quote variants, seq 1003..1006
	udpPkt({224,0,204,14}, 45014, block(1003, tsSec, tsNS + 2, { msgA2, msgK2, msgK3, msgQ2 })),
	-- 4: line 4 production A: underlying values + open interest, seq 500..502
	udpPkt({224,0,204,4},  45004, block(500,  tsSec, tsNS + 3, { msgY1, msgY2, msgD1 })),
	-- 5: line 4 production A: end of day summary, seq 503
	udpPkt({224,0,204,4},  45004, block(503,  tsSec, tsNS + 4, { msgF1 })),
	-- 6: line 4 production A: admin text (odd block, pad byte), seq 504
	udpPkt({224,0,204,4},  45004, block(504,  tsSec, tsNS + 5, { msgC1 })),
	-- 7: line 4 production A: admin with zero data length (odd block), seq 505
	udpPkt({224,0,204,4},  45004, block(505,  tsSec, tsNS + 6, { msgC2 })),
	-- 8: line 220 production B: series mapping messages, seq 1..2
	udpPkt({224,0,206,105}, 45105, block(1,   tsSec, tsNS + 7, { msgR1, msgR2 })),
	-- 9: GTH line 202 production B: session indicator 2, retransmitted block
	udpPkt({224,0,200,129}, 48002, block(77,  tsSec, tsNS + 8, { msgQG }, { sessionInd = 2, retrans = "V" })),
	-- 10: GTH line 201 production A: OPRA generated start of day, session 'X', seq 0
	udpPkt({224,0,200,1},  48001, block(0,    tsSec, tsNS + 9, { msgHC }, { sessionInd = string.byte("X") })),
	-- 11: line 40 retransmission A: retransmitted copy of the a trade
	udpPkt({224,0,204,167}, 46040, block(1000, tsSec, tsNS,     { msgA1 }, { retrans = "V" })),
	-- 12: line 96 playback test A: the indicator F long quote
	udpPkt({224,0,205,96}, 47096, block(1,    tsSec, tsNS + 10, { msgK3 })),
	-- 13: line 1 production A: valid message then unknown category 'z';
	--     only the first message can be decoded
	udpPkt({224,0,204,1},  45001, block(10,   tsSec, tsNS + 11, { msgA2, msgZZ })),

	-- negative cases: none of these may produce rows
	-- 14: correct group, wrong port
	udpPkt({224,0,204,14}, 12345, block(9999, tsSec, tsNS, { msgA1 })),
	-- 15: CTS/CQS lookalike group on the shared 224.0.200.x subnet
	udpPkt({224,0,200,60}, 47001, block(9999, tsSec, tsNS, { msgA1 })),
	-- 16: OPRA group + port but wrong block version
	udpPkt({224,0,204,14}, 45014, block(9999, tsSec, tsNS, { msgA1 }, { version = 5 })),
	-- 17: OPRA group + port but wrong data feed indicator
	udpPkt({224,0,204,14}, 45014, block(9999, tsSec, tsNS, { msgA1 }, { feed = "C" })),
}

------------------------------------------------------------------------------
-- pcap output: nanosecond magic, one packet per second
------------------------------------------------------------------------------
local outName = arg[1] or "opra6_test.pcap"
local f = assert(io.open(outName, "wb"))

f:write(le32(0xa1b23c4d), le16(2), le16(4), le32(0), le32(0), le32(65535), le32(1))

local sec = 1751600000
for i, p in ipairs(pkts) do
	f:write(le32(sec + i - 1), le32(0), le32(#p), le32(#p), p)
end
f:close()

print(string.format("wrote %s: %d packets (13 opra + 4 negative), 21 decodable messages", outName, #pkts))
