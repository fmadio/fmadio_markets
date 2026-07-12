------------------------------------------------------------------------------
--
-- validate_synthetic.lua
--
-- Runs the fmadio_markets decoder (-p opra) over the generated validation
-- pcap and checks every field of every OPRA Pillar v6 message category in the
-- parquet output against the known values from gen_pcap.lua, using the duckdb
-- CLI.
--
-- usage: luajit validate_synthetic.lua [decoder] [pcap] [parquet]
--
------------------------------------------------------------------------------

local DECODER = arg[1] or "../../../src/fmadio_markets"
local PCAP    = arg[2] or "opra6_test.pcap"
local PARQUET = arg[3] or "opra6_test.parq"

local TBL = "read_parquet('" .. PARQUET .. "')"

------------------------------------------------------------------------------
-- run the decoder
------------------------------------------------------------------------------
local cmd = string.format("%s -p opra -r %s -o %s 2>/dev/null", DECODER, PCAP, PARQUET)
local ok = os.execute(cmd)
if ok ~= 0 and ok ~= true then
	print("FAIL: decoder did not run: " .. cmd)
	os.exit(1)
end

------------------------------------------------------------------------------
-- duckdb query helper: returns first line of csv output, trimmed
------------------------------------------------------------------------------
local function query(sql)
	local p = assert(io.popen("duckdb -csv -noheader -c \"" .. sql .. "\" 2>&1"))
	local out = p:read("*a")
	p:close()
	return (out:gsub("%s+$", ""))
end

-- N(col): NULL safe varchar rendering so expected strings are exact
local function N(col)
	return "coalesce(" .. col .. "::VARCHAR, 'NULL')"
end

-- D(col): DECIMAL(20,8) via DOUBLE for compact rendering (195.5 not 195.50000000)
local function D(col)
	return "coalesce(" .. col .. "::DOUBLE::VARCHAR, 'NULL')"
end

------------------------------------------------------------------------------
-- checks: { name, sql, expected }
------------------------------------------------------------------------------
local checks =
{
	-- transport layer -------------------------------------------------------
	{ "row count (negatives rejected, unknown category stops the block)",
	  "SELECT count(*) FROM " .. TBL,
	  "21" },

	{ "implicit sequence numbering, line 14 originals in wire order",
	  "SELECT string_agg(msgCategory || msgSeqNo::VARCHAR, ' ' ORDER BY pcapTS, msgSeqNo) FROM " .. TBL .. " WHERE lineNumber = 14 AND retransmission IS NULL",
	  "a1000 k1001 q1002 H1002 a1003 k1004 k1005 q1006" },

	{ "block timestamp ns on every row",
	  "SELECT count(*) FROM " .. TBL .. " WHERE blockTimestampNS BETWEEN 1692700000123456789 AND 1692700000123456800",
	  "21" },

	{ "pcap timestamp ns on every row",
	  "SELECT count(*) FROM " .. TBL .. " WHERE pcapTS BETWEEN 1751600000000000000 AND 1751600016000000000",
	  "21" },

	{ "stream B rows (line 220 + GTH 202)",
	  "SELECT count(*) FROM " .. TBL .. " WHERE feedStream = 'B'",
	  "3" },

	{ "space message types preserved as ' '",
	  "SELECT count(*) FROM " .. TBL .. " WHERE msgType = ' '",
	  "12" },

	{ "retransmitted rows",
	  "SELECT count(*) FROM " .. TBL .. " WHERE retransmission = 'V'",
	  "2" },

	-- category a ------------------------------------------------------------
	{ "a trade AAPL (upper case type, header fields, extended session)",
	  "SELECT participantId || '|' || msgType || '|' || symbol || '|' || putCall || '|' || expirationYear::VARCHAR || '|' || expirationMonth::VARCHAR || '|' || expirationDay::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || volume::VARCHAR || '|' || " .. D("premiumPrice") .. " || '|' || tradeIdentifier::VARCHAR || '|' || tradingSessionId::VARCHAR || '|' || transactionId::VARCHAR || '|' || participantRefNo::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'a' AND lineNumber = 14 AND msgSeqNo = 1000",
	  "C|I|AAPL|C|2023|8|18|195.5|25|3.42|0|1|287454020|7" },

	{ "a trade MSFT (lower case type, denom I strike, denom A premium)",
	  "SELECT participantId || '|' || msgType || '|' || symbol || '|' || putCall || '|' || expirationYear::VARCHAR || '|' || expirationMonth::VARCHAR || '|' || expirationDay::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || volume::VARCHAR || '|' || " .. D("premiumPrice") .. " || '|' || tradingSessionId::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'a' AND msgSeqNo = 1003",
	  "Q|e|MSFT|C|2026|1|2|425.0|3|9.1|0" },

	-- category k ------------------------------------------------------------
	{ "k long quote SPY, indicator O, double appendage",
	  "SELECT msgIndicator || '|' || symbol || '|' || putCall || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || bidSize::VARCHAR || '|' || " .. D("offerPrice") .. " || '|' || offerSize::VARCHAR || '|' || bestBidParticipantId || '|' || " .. D("bestBidPrice") .. " || '|' || bestBidSize::VARCHAR || '|' || bestOfferParticipantId || '|' || " .. D("bestOfferPrice") .. " || '|' || bestOfferSize::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'k' AND msgSeqNo = 1001",
	  "O|SPY|P|445.0|3.41|10|3.44|12|N|3.42|5|Q|3.43|6" },

	{ "k long quote XSP, indicator M, best bid appendage only (denoms C/D)",
	  "SELECT msgIndicator || '|' || symbol || '|' || putCall || '|' || expirationMonth::VARCHAR || '|' || expirationDay::VARCHAR || '|' || expirationYear::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || bidSize::VARCHAR || '|' || " .. D("offerPrice") .. " || '|' || offerSize::VARCHAR || '|' || bestBidParticipantId || '|' || " .. D("bestBidPrice") .. " || '|' || bestBidSize::VARCHAR || '|' || " .. N("bestOfferParticipantId") .. " || '|' || " .. D("bestOfferPrice") .. " FROM " .. TBL .. " WHERE msgCategory = 'k' AND msgSeqNo = 1004",
	  "M|XSP|P|12|19|2025|5500.0|1.2345|100|2.3456|50|C|1.2|9|NULL|NULL" },

	{ "k long quote TSLA, indicator F, no appendage",
	  "SELECT msgIndicator || '|' || symbol || '|' || putCall || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || " .. D("offerPrice") .. " || '|' || " .. N("bestBidParticipantId") .. " || '|' || " .. N("bestOfferParticipantId") .. " FROM " .. TBL .. " WHERE msgCategory = 'k' AND msgSeqNo = 1005",
	  "F|TSLA|C|300.0|5.0|5.1|NULL|NULL" },

	-- category q ------------------------------------------------------------
	{ "q short quote IWM, indicator C, best offer appendage, implied denoms",
	  "SELECT msgIndicator || '|' || symbol || '|' || putCall || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || bidSize::VARCHAR || '|' || " .. D("offerPrice") .. " || '|' || offerSize::VARCHAR || '|' || " .. N("bestBidParticipantId") .. " || '|' || bestOfferParticipantId || '|' || " .. D("bestOfferPrice") .. " || '|' || bestOfferSize::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'q' AND msgSeqNo = 1002",
	  "C|IWM|C|225.5|1.23|4|1.25|9|NULL|Z|1.24|3" },

	{ "q short quote RUT, zero quote (cancel), prices are 0 not NULL",
	  "SELECT symbol || '|' || putCall || '|' || expirationMonth::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || bidSize::VARCHAR || '|' || " .. D("offerPrice") .. " || '|' || offerSize::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'q' AND msgSeqNo = 1006",
	  "RUT|P|11|1900.0|0.0|0|0.0|0" },

	-- category H ------------------------------------------------------------
	{ "H line integrity, seq of last transmitted message, no series columns",
	  "SELECT participantId || '|' || msgType || '|' || msgSeqNo::VARCHAR || '|' || " .. N("symbol") .. " || '|' || " .. N("strikePrice") .. " || '|' || " .. N("msgIndicator") .. " FROM " .. TBL .. " WHERE msgCategory = 'H' AND lineNumber = 14",
	  "O|N|1002|NULL|NULL|NULL" },

	{ "H start of day on GTH line 201, session indicator 'X', block seq 0",
	  "SELECT participantId || '|' || msgType || '|' || msgSeqNo::VARCHAR || '|' || sessionIndicator::VARCHAR || '|' || lineNumber::VARCHAR || '|' || feedStream FROM " .. TBL .. " WHERE msgCategory = 'H' AND lineNumber = 201",
	  "O|C|0|88|201|A" },

	-- category Y ------------------------------------------------------------
	{ "Y underlying value, index based on last sale",
	  "SELECT symbol || '|' || msgType || '|' || " .. D("indexValue") .. " || '|' || " .. N("bidIndexValue") .. " || '|' || " .. N("offerIndexValue") .. " FROM " .. TBL .. " WHERE msgCategory = 'Y' AND msgType = ' '",
	  "SPX| |4456.7|NULL|NULL" },

	{ "Y underlying value, index based on bid and offer",
	  "SELECT symbol || '|' || msgType || '|' || " .. N("indexValue") .. " || '|' || " .. D("bidIndexValue") .. " || '|' || " .. D("offerIndexValue") .. " FROM " .. TBL .. " WHERE msgCategory = 'Y' AND msgType = 'I'",
	  "NDX|I|NULL|16500.55|16501.23" },

	-- category d ------------------------------------------------------------
	{ "d open interest",
	  "SELECT participantId || '|' || symbol || '|' || putCall || '|' || " .. D("strikePrice") .. " || '|' || openInterestVolume::VARCHAR || '|' || " .. N("volume") .. " FROM " .. TBL .. " WHERE msgCategory = 'd'",
	  "M|AAPL|C|195.5|5000|NULL" },

	-- category f ------------------------------------------------------------
	{ "f end of day summary (negative net change, 8 byte underlying denom H)",
	  "SELECT symbol || '|' || volume::VARCHAR || '|' || openInterestVolume::VARCHAR || '|' || " .. D("openPrice") .. " || '|' || " .. D("highPrice") .. " || '|' || " .. D("lowPrice") .. " || '|' || " .. D("lastPrice") .. " || '|' || " .. D("netChange") .. " || '|' || " .. D("underlyingPrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || " .. D("offerPrice") .. " FROM " .. TBL .. " WHERE msgCategory = 'f'",
	  "AAPL|1234|5678|3.4|3.5|3.3|3.45|-0.05|195.5|3.44|3.46" },

	-- category C ------------------------------------------------------------
	{ "C admin text",
	  "SELECT adminText FROM " .. TBL .. " WHERE msgCategory = 'C' AND msgSeqNo = 504",
	  "HELLO OPRA" },

	{ "C admin with zero data length, text is NULL",
	  "SELECT " .. N("adminText") .. " FROM " .. TBL .. " WHERE msgCategory = 'C' AND msgSeqNo = 505",
	  "NULL" },

	-- category R ------------------------------------------------------------
	{ "R series mapping TSLA (denom I)",
	  "SELECT msgType || '|' || symbol || '|' || putCall || '|' || expirationMonth::VARCHAR || '|' || expirationDay::VARCHAR || '|' || expirationYear::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || multicastLineNumber::VARCHAR || '|' || lineNumber::VARCHAR || '|' || feedStream FROM " .. TBL .. " WHERE msgCategory = 'R' AND msgSeqNo = 1",
	  "A|TSLA|C|1|19|2024|250.0|37|220|B" },

	{ "R series mapping SPY (denom E, put month V)",
	  "SELECT symbol || '|' || putCall || '|' || expirationMonth::VARCHAR || '|' || " .. D("strikePrice") .. " || '|' || multicastLineNumber::VARCHAR FROM " .. TBL .. " WHERE msgCategory = 'R' AND msgSeqNo = 2",
	  "SPY|P|10|450.0|96" },

	-- classifier: feeds and lines -------------------------------------------
	{ "GTH retransmitted quote: line 202 stream B, session 2, indicator A",
	  "SELECT lineNumber::VARCHAR || '|' || feedStream || '|' || sessionIndicator::VARCHAR || '|' || retransmission || '|' || msgIndicator || '|' || symbol || '|' || " .. D("strikePrice") .. " || '|' || " .. D("bidPrice") .. " || '|' || " .. D("offerPrice") .. " FROM " .. TBL .. " WHERE lineNumber = 202",
	  "202|B|2|V|A|QQQ|480.0|2.0|2.1" },

	{ "retransmission feed group: line 40 carries the retransmitted a trade",
	  "SELECT lineNumber::VARCHAR || '|' || retransmission || '|' || msgSeqNo::VARCHAR || '|' || msgCategory || '|' || symbol || '|' || " .. D("premiumPrice") .. " FROM " .. TBL .. " WHERE lineNumber = 40",
	  "40|V|1000|a|AAPL|3.42" },

	{ "playback test feed group: line 96 carries the indicator F quote",
	  "SELECT lineNumber::VARCHAR || '|' || feedStream || '|' || msgCategory || '|' || msgIndicator || '|' || symbol FROM " .. TBL .. " WHERE lineNumber = 96",
	  "96|A|k|F|TSLA" },

	-- robustness -------------------------------------------------------------
	{ "unknown category stops the block walk: line 1 decodes only the first message",
	  "SELECT count(*)::VARCHAR || '|' || string_agg(msgCategory || '/' || symbol, ',') FROM " .. TBL .. " WHERE lineNumber = 1",
	  "1|a/MSFT" },

	{ "no rows from unknown categories or negative packets",
	  "SELECT count(*) FROM " .. TBL .. " WHERE msgCategory NOT IN ('a','d','f','k','q','C','H','R','Y') OR msgSeqNo = 9999",
	  "0" },
}

------------------------------------------------------------------------------
-- run all checks
------------------------------------------------------------------------------
local pass, fail = 0, 0
for _, c in ipairs(checks) do
	local name, sql, expect = c[1], c[2], c[3]
	local got = query(sql)
	if got == expect then
		pass = pass + 1
		print(string.format("PASS  %s", name))
	else
		fail = fail + 1
		print(string.format("FAIL  %s", name))
		print(string.format("      expected [%s]", expect))
		print(string.format("      got      [%s]", got))
	end
end

print(string.format("\n%d/%d checks passed", pass, pass + fail))
os.exit(fail == 0 and 0 or 1)
