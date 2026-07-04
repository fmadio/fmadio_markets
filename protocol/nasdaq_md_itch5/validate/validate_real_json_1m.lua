------------------------------------------------------------------------------
--
-- verify_real_json_1m.lua
--
-- Field level verification of the ITCH 5.0 decoder against an independent
-- decode: the OMI (Open Markets Initiative) wireshark lua dissector output
-- exported by tshark as ek json (1M packet slice, zstd compressed).
--
-- The ek json is flattened to one csv row per ITCH message and joined in
-- duckdb against the decoder parquet on (mold session, sequence number),
-- comparing 17 fields per message.
--
-- tshark -T ek serialization quirks handled here (see nasdaq_md_itch5.md
-- section 9.3):
--   1. mixed-type packets emit duplicate json keys (invalid json). the
--      parser walks the raw text in order so nothing is lost
--   2. per-message fields are grouped by message-type subtree, not wire
--      order. values are tagged with their subtree and consumed from a
--      per (message type, field) queue while walking messagetype[] in
--      wire order
--   3. the Y message names its locate field 'locatecode', not 'stocklocate'
--
-- usage: luajit verify_real_json_1m.lua <parquet> <json.zst> [decoder] [pcap.zst]
--        (if the parquet is missing and decoder+pcap are given, it is decoded)
--
------------------------------------------------------------------------------

local PARQUET = arg[1] or "ny4-xnas-tvitch-20230822.parquet"
local JSON    = arg[2] or "../../../data/protocol/nasdaq_md_itch5/ny4-xnas-tvitch-20230822.pcap.tshark.json.1m.zst"
local DECODER = arg[3]
local PCAP    = arg[4]
local CSVOUT  = "omi_json_1m.csv"

print(string.format("parquet : %s", PARQUET))
print(string.format("json    : %s", JSON))

------------------------------------------------------------------------------
-- decode the pcap if the parquet is not present
------------------------------------------------------------------------------
local f = io.open(PARQUET, "r")
if f then
	f:close()
else
	if not (DECODER and PCAP) then
		print("FAIL: " .. PARQUET .. " missing; run 'make real' first or pass decoder + pcap")
		os.exit(1)
	end
	local cmd = string.format("zstdcat %s | %s -o %s", PCAP, DECODER, PARQUET)
	print("decoding: " .. cmd)
	local ok = os.execute(cmd)
	if (ok ~= 0 and ok ~= true) or not io.open(PARQUET, "r") then
		print("FAIL: decoder did not produce " .. PARQUET)
		os.exit(1)
	end
end

------------------------------------------------------------------------------
-- field -> message types that carry it (spec field tables)
------------------------------------------------------------------------------
local ALL = "SRHYLVWKJhAFECXDUPQBINO"

local FIELD_TYPES =
{
	messagetype            = ALL,
	stocklocate            = "SRHLVWKJhAFECXDUPQBINO",   -- all but Y
	locatecode             = "Y",
	trackingnumber         = ALL,
	timestamp              = ALL,
	stock                  = "RHYLKJhAFPQINO",
	orderreferencenumber   = "AFECXDP",
	tradingstate           = "H",
	regshoaction           = "Y",
	mpid                   = "L",
	marketcategory         = "R",
	roundlotsize           = "R",
	issueclassification    = "R",
	eventcode              = "S",
	primarymarketmaker     = "L",
	marketmakermode        = "L",
	marketparticipantstate = "L",
}

-- csv column order (locatecode folds into stocklocate)
local OUT_FIELDS =
{
	"messagetype", "stocklocate", "trackingnumber", "timestamp", "stock",
	"orderreferencenumber", "tradingstate", "regshoaction", "mpid",
	"marketcategory", "roundlotsize", "issueclassification", "eventcode",
	"primarymarketmaker", "marketmakermode", "marketparticipantstate",
}

-- ek subtree marker key -> owning message type
local MARKER2TYPE =
{
	systemeventmessage = "S", stockdirectorymessage = "R",
	stocktradingactionmessage = "H",
	regshoshortsalepricetestrestrictedindicatormessage = "Y",
	marketparticipantpositionmessage = "L",
	mwcbdeclinelevelmessage = "V", mwcbstatusmessage = "W",
	ipoquotingperiodupdatemessage = "K", quotingperiodupdatemessage = "K",
	luldauctioncollarmessage = "J", operationalhaltmessage = "h",
	addordermessage = "A", addordernompidattributionmessage = "A",
	addordermpidattributionmessage = "F", addorderwithmpidmessage = "F",
	orderexecutedmessage = "E", orderexecutedwithpricemessage = "C",
	ordercancelmessage = "X", orderdeletemessage = "D",
	orderreplacemessage = "U", trademessage = "P",
	tradenoncrossmessage = "P", crosstrademessage = "Q",
	brokentrademessage = "B", noiimessage = "I",
	netorderimbalanceindicatormessage = "I",
	retailpriceimprovementindicatormessage = "N",
	directlistingwithcapitalraisepricediscoverymessage = "O",
}

local function carries(field, mtype)
	local set = FIELD_TYPES[field]
	return set and string.find(set, mtype, 1, true) ~= nil
end

------------------------------------------------------------------------------
-- flatten the ek json to one csv row per message
------------------------------------------------------------------------------
print("\n[1/2] flattening ek json to " .. CSVOUT .. " ...")

local out = assert(io.open(CSVOUT, "w"))
out:write("pcapTS,session,seq," .. table.concat(OUT_FIELDS, ",") .. "\n")

local jp = assert(io.popen("zstdcat " .. JSON))
local msgTotal, pktTotal, badLines = 0, 0, 0

for line in jp:lines() do
	repeat  -- break = continue
		if not line:find('"layers"', 1, true) then
			break
		end
		if not line:match("}%s*$") then
			badLines = badLines + 1   -- truncated (byte sliced file)
			break
		end

		local epoch = line:match('"frame_frame_time_epoch":"([%d%.]+)"')
		if not epoch then
			break
		end
		local pcapTS = epoch:gsub("%.", "")

		local omiStart = line:find('"omi_', 1, true)
		if not omiStart then
			break
		end
		local seg = line:sub(omiStart)

		-- walk every omi key in raw order; values are quoted scalars or
		-- arrays of quoted scalars. queue per (subtree tag, field)
		local vals, session, seq = {}, nil, nil
		local tag = "*"
		local pos = 1
		while true do
			local s, e, key = seg:find('"omi_[%w_]-_([a-z0-9]+)":', pos)
			if not s then
				break
			end
			pos = e + 1
			local c = seg:sub(pos, pos)
			local items = nil
			if c == '"' then
				local _, e2, v = seg:find('^"([^"]*)"', pos)
				items = { v }
				pos = e2 + 1
			elseif c == "[" then
				local _, e2, arr = seg:find("^(%b[])", pos)
				items = {}
				for v in arr:gmatch('"([^"]*)"') do
					items[#items + 1] = v
				end
				pos = e2 + 1
			end

			if key == "session" and items then
				session = items[1]:gsub("%s+$", "")
			elseif key == "sequencenumber" and items then
				seq = tonumber(items[1])
			elseif MARKER2TYPE[key] then
				tag = MARKER2TYPE[key]
			elseif FIELD_TYPES[key] and items then
				local qk = tag .. "|" .. key
				local q = vals[qk]
				if not q then
					q = {}
					vals[qk] = q
				end
				for _, v in ipairs(items) do
					q[#q + 1] = v
				end
			end
		end

		local types = vals["*|messagetype"]
		if not types or not seq then
			break   -- heartbeat / end of session
		end

		pktTotal = pktTotal + 1
		local cursor = {}
		for i, t in ipairs(types) do
			local row = { pcapTS, session, tostring(seq + i - 1) }
			for _, fld in ipairs(OUT_FIELDS) do
				local src = fld
				if fld == "stocklocate" and t == "Y" then
					src = "locatecode"
				end
				local v = ""
				if fld == "messagetype" then
					v = t
				elseif carries(src, t) then
					local qk = t .. "|" .. src
					local q = vals[qk]
					local c2 = (cursor[qk] or 0) + 1
					if q and q[c2] then
						v = q[c2]
						cursor[qk] = c2
					end
				end
				-- strip padding and any embedded csv metachars
				v = v:gsub("%s+$", ""):gsub("[,\r\n]", " ")
				row[#row + 1] = v
			end
			out:write(table.concat(row, ",") .. "\n")
			msgTotal = msgTotal + 1
		end
	until true
end
jp:close()
out:close()

print(string.format("      %d packets, %d messages, %d truncated lines skipped",
	pktTotal, msgTotal, badLines))

------------------------------------------------------------------------------
-- duckdb field comparison
------------------------------------------------------------------------------
print("\n[2/2] comparing 17 fields per message in duckdb...\n")

local function query(sql)
	local p = assert(io.popen("duckdb -csv -noheader -c \"" .. sql .. "\" 2>&1"))
	local o = p:read("*a")
	p:close()
	return (o:gsub("%s+$", ""))
end

local DIFFS =
{
	{ "pcapTS",             "j.pcapTS != p.pcapTS" },
	{ "msgType",            "j.messagetype != p.msgType" },
	{ "stockLocate",        "j.stocklocate != p.stockLocate" },
	{ "trackingNumber",     "j.trackingnumber != p.trackingNumber" },
	{ "timestampNS",        "j.ts != p.timestampNS" },
	{ "stock",              "j.stock IS DISTINCT FROM p.stock" },
	{ "orderRefNumber",     "j.ordRef IS DISTINCT FROM p.orderReferenceNumber" },
	{ "tradingState",       "j.tradingState IS DISTINCT FROM p.tradingState" },
	{ "regSHOAction",       "j.regSHO IS DISTINCT FROM p.regSHOAction" },
	{ "mpid",               "j.mpid IS DISTINCT FROM p.mpid" },
	{ "marketCategory",     "j.mktCat IS DISTINCT FROM p.marketCategory" },
	{ "roundLotSize",       "j.roundlotsize IS DISTINCT FROM p.roundLotSize" },
	{ "issueClassification","j.issueClass IS DISTINCT FROM p.issueClassification" },
	{ "eventCode",          "j.eventCode IS DISTINCT FROM p.eventCode" },
	{ "primaryMarketMaker", "j.pmm IS DISTINCT FROM p.primaryMarketMaker" },
	{ "marketMakerMode",    "j.mmMode IS DISTINCT FROM p.marketMakerMode" },
	{ "mktParticipantState","j.mpState IS DISTINCT FROM p.marketParticipantState" },
}

local sums = {}
for _, d in ipairs(DIFFS) do
	sums[#sums + 1] = string.format("sum(CASE WHEN %s THEN 1 ELSE 0 END)", d[2])
end

local sql = string.format([[
WITH j AS (
  SELECT pcapTS, session, seq, messagetype, stocklocate, trackingnumber,
         timestamp AS ts,
         nullif(trim(stock),'') AS stock,
         orderreferencenumber AS ordRef,
         nullif(trim(tradingstate),'') AS tradingState,
         nullif(trim(regshoaction),'') AS regSHO,
         nullif(trim(mpid),'') AS mpid,
         nullif(trim(marketcategory),'') AS mktCat,
         roundlotsize,
         nullif(trim(issueclassification),'') AS issueClass,
         nullif(trim(eventcode),'') AS eventCode,
         nullif(trim(primarymarketmaker),'') AS pmm,
         nullif(trim(marketmakermode),'') AS mmMode,
         nullif(trim(marketparticipantstate),'') AS mpState
  FROM read_csv('%s', header=true)
),
p AS (SELECT * FROM '%s')
SELECT (SELECT count(*) FROM j), count(*), %s
FROM j JOIN p ON j.session = p.moldSession AND j.seq = p.moldSeqNo
]], CSVOUT, PARQUET, table.concat(sums, ", "))

local res = query(sql)
local fields = {}
for v in res:gmatch("[^,]+") do
	fields[#fields + 1] = v
end

local omiMsgs = tonumber(fields[1])
local matched = tonumber(fields[2])
if not omiMsgs then
	print("FAIL  duckdb comparison query failed:")
	print(res)
	os.exit(1)
end

print(string.format("json messages   : %d", omiMsgs))
print(string.format("matched in parq : %d", matched))

local pass, fail = 0, 0
local function check(name, ok, detail)
	if ok then
		pass = pass + 1
		print(string.format("PASS  %s", name))
	else
		fail = fail + 1
		print(string.format("FAIL  %s (%s)", name, detail))
	end
end

check("every json message found in parquet", matched == omiMsgs,
	string.format("%d of %d matched", matched, omiMsgs))

for i, d in ipairs(DIFFS) do
	local n = tonumber(fields[2 + i]) or -1
	check("field " .. d[1], n == 0, string.format("%d mismatches", n))
end

os.remove(CSVOUT)

print(string.format("\n%d/%d checks passed", pass, pass + fail))
os.exit(fail == 0 and 0 or 1)
