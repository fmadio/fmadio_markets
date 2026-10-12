------------------------------------------------------------------------------
--
-- validate_omi.lua
--
-- Cross-validates a fmadio_markets decoder against the OMI (Open Markets
-- Initiative) wireshark lua dissectors, using tshark as an independent
-- reference decoder. This is the REFERENCE EXAMPLE for OMI cross-validation:
-- OPRA Pillar v6 is the protocol under test, and the sections marked
-- "protocol specific" are the only parts that change for another protocol.
--
-- pipeline (one numbered section banner per step below):
--
--   1. fmadio_markets decoder:   pcap -> parquet
--   2. tshark + OMI dissector:   pcap -> one line per packet, tab separated
--      fields, '|' separated occurrences within a field (-E occurrence=a
--      preserves wire order per field, see doc/validation.md tshark caveats)
--   3. flatten the per-packet field lists into per-message rows: walk the
--      message category list and pop each field the category contains from
--      that field's occurrence queue. The popping order within one field
--      must mirror the wire order; across different fields order is free
--   4. dump the decoder parquet in the same normalized shape via duckdb
--   5. compare field by field on the per-message key, print diffs, exit
--      nonzero unless every compared message matches
--
-- the normalized row is declared ONCE in FIELDS: each entry names the field,
-- how it compares (str = exact string, num = number with relative epsilon
-- for denominator scaled prices) and the duckdb expression that produces it
-- from the parquet. Both the SQL and the parquet row parser are generated
-- from that table, so the two sides cannot drift apart.
--
-- adapting this to another protocol:
--
--   1. point DISSECTOR at the protocol's OMI lua file, set the OMI field
--      prefix and the decoder -p name
--   2. choose a per-message join key both sides can compute independently
--      (here: ipDst:portDst:msgSeqNo, with msgSeqNo = blockSeqNo + message
--      index in block - the same implicit numbering the decoder uses)
--   3. declare the normalized row in FIELDS (name, compare kind, parquet SQL)
--   4. list the tshark fields to extract in TSHARK_FIELDS
--   5. write one flatten branch per message category, popping fields in wire
--      order; consume-but-do-not-store categories that must not be compared,
--      and skip the rest of the block when framing is lost
--
-- known OPRA limits: see opra_md_pillar6.md 9.2 and doc/validation.md
-- (kip heuristic, tradingSessionId, H control blocks, unknown categories).
--
-- usage: luajit validate_omi.lua [decoder] [pcap] [omi_dissector.lua] [parquet]
--
------------------------------------------------------------------------------

local DECODER   = arg[1] or "../../../src/fmadio_markets"
local PCAP      = arg[2] or "omi_slice.pcap"
local DISSECTOR = arg[3] or "../../../omi-wireshark-lua/Siac/Opra/Output/Siac_Opra_Output_Obi_v6_3_a_Dissector.lua"
local PARQUET   = arg[4] or "omi_slice.parq"

local PROTOCOL  = "opra"							-- decoder -p name
local OMI       = "siac.opra.output.obi.v6.3.a."	-- OMI field name prefix

------------------------------------------------------------------------------
-- generic helpers
------------------------------------------------------------------------------

-- split keeping empty fields ("a||b" -> {"a", "", "b"})
local function split(line, sep)
	local out = {}
	local pos = 1
	while true do
		local s = line:find(sep, pos, true)
		if s == nil then
			out[#out + 1] = line:sub(pos)
			return out
		end
		out[#out + 1] = line:sub(pos, s - 1)
		pos = s + 1
	end
end

local function trim(s)
	return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

------------------------------------------------------------------------------
-- protocol specific: OPRA denominator codes (opra_md_pillar6.md 2.4).
-- OMI exposes prices as raw integers plus a separate denominator code field;
-- the fmadio decoder stores the scaled double, so the flattener applies the
-- same scaling
------------------------------------------------------------------------------
local function denomScale(code)
	local scale = { A = 1e1, B = 1e2, C = 1e3, D = 1e4, E = 1e5, F = 1e6, G = 1e7, H = 1e8, I = 1.0 }
	return scale[code] or 1.0
end

------------------------------------------------------------------------------
-- protocol specific: the normalized per-message row, shared by both sides.
--   name: row field name used by the flattener in step 3
--   kind: "num" compares as a number (denominator scaled prices),
--         everything else compares as an exact string
--   sql:  duckdb expression producing the field from the decoder parquet
-- NULL renders as '' so an absent field compares equal to a not-popped queue
------------------------------------------------------------------------------
local FIELDS =
{
	{ name = "category",       kind = "str", sql = "msg_category" },
	{ name = "type",           kind = "str", sql = "msg_type" },
	{ name = "indicator",      kind = "str", sql = "coalesce(msg_indicator, '')" },
	{ name = "participantId",  kind = "str", sql = "msg_participantId" },
	{ name = "transactionId",  kind = "str", sql = "msg_transactionId::VARCHAR" },
	{ name = "refNo",          kind = "str", sql = "msg_participantRefNo::VARCHAR" },
	{ name = "symbol",         kind = "str", sql = "trim(coalesce(msg_symbol, ''))" },
	{ name = "expMonthCode",   kind = "str", sql = "coalesce(msg_expirationMonthCode, '')" },
	{ name = "expDay",         kind = "str", sql = "coalesce(msg_expirationDay::VARCHAR, '')" },
	{ name = "expYear",        kind = "str", sql = "coalesce(msg_expirationYear::VARCHAR, '')" },
	{ name = "strikePrice",    kind = "num", sql = "coalesce(msg_strikePrice::VARCHAR, '')" },
	{ name = "bidPrice",       kind = "num", sql = "coalesce(msg_bidPrice::VARCHAR, '')" },
	{ name = "bidSize",        kind = "str", sql = "coalesce(msg_bidSize::VARCHAR, '')" },
	{ name = "offerPrice",     kind = "num", sql = "coalesce(msg_offerPrice::VARCHAR, '')" },
	{ name = "offerSize",      kind = "str", sql = "coalesce(msg_offerSize::VARCHAR, '')" },
	{ name = "bestBidPid",     kind = "str", sql = "coalesce(msg_bestBidParticipantId, '')" },
	{ name = "bestBidPrice",   kind = "num", sql = "coalesce(msg_bestBidPrice::VARCHAR, '')" },
	{ name = "bestBidSize",    kind = "str", sql = "coalesce(msg_bestBidSize::VARCHAR, '')" },
	{ name = "bestOfferPid",   kind = "str", sql = "coalesce(msg_bestOfferParticipantId, '')" },
	{ name = "bestOfferPrice", kind = "num", sql = "coalesce(msg_bestOfferPrice::VARCHAR, '')" },
	{ name = "bestOfferSize",  kind = "str", sql = "coalesce(msg_bestOfferSize::VARCHAR, '')" },
	{ name = "volume",         kind = "str", sql = "coalesce(msg_volume::VARCHAR, '')" },
	{ name = "premiumPrice",   kind = "num", sql = "coalesce(msg_premiumPrice::VARCHAR, '')" },
	{ name = "tradeId",        kind = "str", sql = "coalesce(msg_tradeIdentifier::VARCHAR, '')" },
	{ name = "blockTsSec",     kind = "str", sql = "(hdr_blockTimestampNS // 1000000000)::VARCHAR" },
	{ name = "blockTsNS",      kind = "str", sql = "(hdr_blockTimestampNS % 1000000000)::VARCHAR" },
}

-- categories with a full flatten branch in step 3; parquet rows of other
-- categories are excluded from the dump in step 4
local COMPARED_CATEGORIES = "('a', 'k', 'q')"

------------------------------------------------------------------------------
-- protocol specific: the tshark fields to extract. The first 6 build the
-- per-message key, the rest are the per-message occurrence queues consumed
-- by the flattener
------------------------------------------------------------------------------
local TSHARK_FIELDS =
{
	"ip.dst",
	"udp.dstport",
	OMI .. "blocksequencenumber",
	OMI .. "messagesinblock",
	OMI .. "seconds",
	OMI .. "nanoseconds",
	OMI .. "messagecategory",
	OMI .. "participantid",
	OMI .. "shortequityandindexquotemessagetype",
	OMI .. "longequityandindexquotemessagetype",
	OMI .. "equityandindexlastsalemessagetype",
	OMI .. "controlmessagetype",
	OMI .. "bboindicator",
	OMI .. "messageindicator",
	OMI .. "transactionid",
	OMI .. "participantreferencenumber",
	OMI .. "securitysymbolshort",
	OMI .. "securitysymbol",
	OMI .. "expirationmonth",
	OMI .. "expirationday",
	OMI .. "expirationyear",
	OMI .. "strikepriceshort",
	OMI .. "strikepricedenominatorcode",
	OMI .. "strikeprice",
	OMI .. "premiumpricedenominatorcode",
	OMI .. "bidpriceshort",
	OMI .. "bidsizeshort",
	OMI .. "offerpriceshort",
	OMI .. "offersizeshort",
	OMI .. "bidprice",
	OMI .. "bidsize",
	OMI .. "offerprice",
	OMI .. "offersize",
	OMI .. "volume",
	OMI .. "premiumprice",
	OMI .. "tradeidentifier",
	OMI .. "bestbidparticipantid",
	OMI .. "bestbiddenominatorcode",
	OMI .. "bestbidprice",
	OMI .. "bestbidsize",
	OMI .. "bestofferparticipantid",
	OMI .. "bestofferdenominatorcode",
	OMI .. "bestofferprice",
	OMI .. "bestoffersize",
}

------------------------------------------------------------------------------
-- step 1: run the fmadio_markets decoder
------------------------------------------------------------------------------
local cmd = string.format("%s -p %s -r %s -o %s -t 0 2>/dev/null", DECODER, PROTOCOL, PCAP, PARQUET)
print("decoder: " .. cmd)
local ok = os.execute(cmd)
if ok ~= 0 and ok ~= true then
	print("FAIL: decoder did not run")
	os.exit(1)
end

------------------------------------------------------------------------------
-- step 2: build the tshark command. --disable-protocol kip: the kip
-- heuristic steals small OPRA packets before the OMI heuristic runs
------------------------------------------------------------------------------
local tsharkCmd = "tshark -r " .. PCAP .. " -X lua_script:" .. DISSECTOR .. " --disable-protocol kip -T fields -E occurrence=a -E separator=/t -E 'aggregator=|'"
for _, f in ipairs(TSHARK_FIELDS) do
	tsharkCmd = tsharkCmd .. " -e " .. f
end
tsharkCmd = tsharkCmd .. " 2>/dev/null"
print("tshark : decoding " .. PCAP .. " with " .. DISSECTOR:match("[^/]+$"))

------------------------------------------------------------------------------
-- step 3: flatten tshark packets into per-message normalized rows
------------------------------------------------------------------------------
local omiRow    = {}		-- key -> normalized row
local skipped   = {}		-- key -> true, rest-of-block after an unhandled category
local skipCount = {}		-- category -> messages not compared
local omiTotal  = 0

-- per packet occurrence queues, rebuilt for every packet by the main loop
local queue

local function pop(name)
	return table.remove(queue[OMI .. name], 1) or ""
end

local function popNum(name)
	return tonumber(pop(name)) or 0
end

local function popPrice(name, scale)
	return tostring(popNum(name) / scale)
end

-- protocol specific pop helpers: each mirrors one wire structure ------------

-- 12 byte message header shared by every category; the type and indicator
-- field names are per category in OMI
local function popHeader(cat, typeField, indicatorField)
	local row = {}
	row.category      = cat
	row.participantId = pop("participantid")
	row.type          = pop(typeField)
	row.indicator     = pop(indicatorField)
	row.transactionId = pop("transactionid")
	row.refNo         = pop("participantreferencenumber")
	return row
end

-- 3 byte expiration block (month code, day, 2 digit year)
local function popExpiration(row)
	row.expMonthCode = pop("expirationmonth")
	row.expDay       = pop("expirationday")
	row.expYear      = tostring(2000 + popNum("expirationyear"))
end

-- BBO appendage(s) after a quote body, selected by the BBO indicator
-- (opra_md_pillar6.md 5.3): M/N/P best bid, C/G/K best offer, O both
local function popAppendage(row)
	local ind = row.indicator
	if ind == "M" or ind == "N" or ind == "P" or ind == "O" then
		row.bestBidPid   = pop("bestbidparticipantid")
		row.bestBidPrice = popPrice("bestbidprice", denomScale(pop("bestbiddenominatorcode")))
		row.bestBidSize  = pop("bestbidsize")
	end
	if ind == "C" or ind == "G" or ind == "K" or ind == "O" then
		row.bestOfferPid   = pop("bestofferparticipantid")
		row.bestOfferPrice = popPrice("bestofferprice", denomScale(pop("bestofferdenominatorcode")))
		row.bestOfferSize  = pop("bestoffersize")
	end
end

local tsharkPipe = assert(io.popen(tsharkCmd))
for line in tsharkPipe:lines() do
	local col = split(line, "\t")
	local ipDst    = col[1]
	local portDst  = col[2]
	local blockSeq = tonumber(col[3])		-- nil when tshark did not decode the packet
	local msgCount = tonumber(col[4]) or 0
	local tsSec    = col[5]
	local tsNS     = col[6]

	if blockSeq ~= nil then
		queue = {}
		for i = 7, #TSHARK_FIELDS do
			queue[TSHARK_FIELDS[i]] = split(col[i] or "", "|")
		end
		-- one category entry per message: indexed by message number, never popped
		local category = queue[OMI .. "messagecategory"]

		for i = 0, msgCount - 1 do
			local key = ipDst .. ":" .. portDst .. ":" .. (blockSeq + i)
			local cat = category[i + 1] or "?"
			local row = nil

			-- protocol specific: one branch per category, popping in wire order
			if cat == "q" then			-- Short Equity and Index Quote
				row = popHeader(cat, "shortequityandindexquotemessagetype", "bboindicator")
				row.symbol      = trim(pop("securitysymbolshort"))
				popExpiration(row)
				-- short quote implied denominators: strike /10, prices /100
				row.strikePrice = popPrice("strikepriceshort", 1e1)
				row.bidPrice    = popPrice("bidpriceshort", 1e2)
				row.bidSize     = pop("bidsizeshort")
				row.offerPrice  = popPrice("offerpriceshort", 1e2)
				row.offerSize   = pop("offersizeshort")
				popAppendage(row)
			elseif cat == "k" then		-- Long Equity and Index Quote
				row = popHeader(cat, "longequityandindexquotemessagetype", "bboindicator")
				row.symbol      = trim(pop("securitysymbol"))
				popExpiration(row)
				row.strikePrice = popPrice("strikeprice", denomScale(pop("strikepricedenominatorcode")))
				local prem      = denomScale(pop("premiumpricedenominatorcode"))
				row.bidPrice    = popPrice("bidprice", prem)
				row.bidSize     = pop("bidsize")
				row.offerPrice  = popPrice("offerprice", prem)
				row.offerSize   = pop("offersize")
				popAppendage(row)
			elseif cat == "a" then		-- Equity and Index Last Sale
				row = popHeader(cat, "equityandindexlastsalemessagetype", "messageindicator")
				row.indicator    = ""		-- fmadio only stores the indicator for quotes
				row.symbol       = trim(pop("securitysymbol"))
				popExpiration(row)
				row.strikePrice  = popPrice("strikeprice", denomScale(pop("strikepricedenominatorcode")))
				row.volume       = pop("volume")
				row.premiumPrice = popPrice("premiumprice", denomScale(pop("premiumpricedenominatorcode")))
				row.tradeId      = pop("tradeidentifier")
			elseif cat == "H" then		-- Control: 12 byte header only
				-- consumed but never stored: an H block reuses the last
				-- transmitted seq number, so its key collides with a real
				-- message on the same line
				popHeader(cat, "controlmessagetype", "messageindicator")
				skipCount[cat] = (skipCount[cat] or 0) + 1
			else
				-- no per-message length field: the messages after an unknown
				-- category cannot be located, skip them on both sides
				for j = i + 1, msgCount - 1 do
					skipped[ipDst .. ":" .. portDst .. ":" .. (blockSeq + j)] = true
				end
				skipCount[cat] = (skipCount[cat] or 0) + (msgCount - i)
				break
			end

			if row ~= nil then
				row.blockTsSec = tsSec
				row.blockTsNS  = tsNS
				omiRow[key] = row
				omiTotal = omiTotal + 1
			end
		end
	end
end
tsharkPipe:close()
print(string.format("tshark : %d messages flattened", omiTotal))

------------------------------------------------------------------------------
-- step 4: dump the decoder parquet in the same normalized shape.
-- the SELECT list is generated from FIELDS: key columns first, then one
-- expression per normalized field, in FIELDS order
------------------------------------------------------------------------------
local SQL = "SELECT frame_ipDst, frame_portDst, hdr_msgSeqNo"
for _, f in ipairs(FIELDS) do
	SQL = SQL .. ", " .. f.sql
end
SQL = SQL .. " FROM read_parquet('" .. PARQUET .. "') WHERE msg_category IN " .. COMPARED_CATEGORIES

------------------------------------------------------------------------------
-- step 5: compare per message, field by field
------------------------------------------------------------------------------
local matchCount = 0		-- parquet rows where every field matched
local diffCount  = 0		-- individual field mismatches
local missingOmi = 0		-- parquet rows tshark+OMI did not decode
local missingPq  = 0		-- tshark+OMI rows not in the parquet
local pqSkipped  = 0		-- parquet rows inside skipped block tails
local pqTotal    = 0		-- parquet rows of the compared categories
local MAX_REPORT = 20		-- stop printing diffs after this many

local duckPipe = assert(io.popen("duckdb -list -noheader -c \"" .. SQL .. "\" 2>&1"))
for line in duckPipe:lines() do
	local col = split(line, "|")
	local key = col[1] .. ":" .. col[2] .. ":" .. col[3]
	pqTotal = pqTotal + 1

	-- parse the row by FIELDS order, mirroring the generated SELECT list
	local pq = {}
	for i, f in ipairs(FIELDS) do
		pq[f.name] = col[3 + i] or ""
	end

	if skipped[key] then
		pqSkipped = pqSkipped + 1
	elseif omiRow[key] == nil then
		missingOmi = missingOmi + 1
		if missingOmi <= MAX_REPORT then
			print("DIFF " .. key .. " : in parquet but not decoded by tshark+OMI (category " .. pq.category .. ")")
		end
	else
		local omi = omiRow[key]
		local rowOk = true
		for _, f in ipairs(FIELDS) do
			local a = omi[f.name] or ""
			local b = pq[f.name]
			local same
			if f.kind == "num" and tonumber(a) ~= nil and tonumber(b) ~= nil then
				same = math.abs(tonumber(a) - tonumber(b)) <= 1e-9 * math.max(1.0, math.abs(tonumber(a)))
			else
				same = (a == b)
			end
			if not same then
				rowOk = false
				diffCount = diffCount + 1
				if diffCount <= MAX_REPORT then
					print(string.format("DIFF %s : %s omi=[%s] parquet=[%s]", key, f.name, a, b))
				end
			end
		end
		if rowOk then
			matchCount = matchCount + 1
		end
		omiRow[key] = nil		-- consumed: leftovers are missing from the parquet
	end
end
duckPipe:close()

-- anything left on the tshark side was not in the parquet
for key, row in pairs(omiRow) do
	if not skipped[key] then
		missingPq = missingPq + 1
		if missingPq <= MAX_REPORT then
			print("DIFF " .. key .. " : decoded by tshark+OMI but not in parquet (category " .. row.category .. ")")
		end
	end
end

------------------------------------------------------------------------------
-- summary: stable key : value lines, then a single PASS/FAIL verdict line
------------------------------------------------------------------------------
print("")
print(string.format("parquet messages %s : %d", COMPARED_CATEGORIES, pqTotal))
print(string.format("full row matches         : %d", matchCount))
print(string.format("field diffs              : %d", diffCount))
print(string.format("missing from tshark+OMI  : %d", missingOmi))
print(string.format("missing from parquet     : %d", missingPq))
print(string.format("skipped block tails      : %d", pqSkipped))
for cat, n in pairs(skipCount) do
	print(string.format("skipped category [%s]     : %d messages (not compared)", cat, n))
end

if diffCount == 0 and missingOmi == 0 and missingPq == 0 and matchCount > 0 then
	print("PASS: tshark+OMI and fmadio_markets agree on all " .. matchCount .. " compared messages")
	os.exit(0)
end
print("FAIL")
os.exit(1)
