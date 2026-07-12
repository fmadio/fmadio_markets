------------------------------------------------------------------------------
--
-- validate.lua
--
-- Runs the fmadio_markets decoder over the generated validation pcap and
-- checks every field of every ITCH 5.0 message type in the parquet output
-- against the known values from gen_pcap.lua, using the duckdb CLI.
--
-- usage: luajit validate.lua [decoder] [pcap] [parquet]
--
------------------------------------------------------------------------------

local DECODER = arg[1] or "../../../src/fmadio_markets"
local PCAP    = arg[2] or "itch5_test.pcap"
local PARQUET = arg[3] or "itch5_test.parq"

local TBL = "read_parquet('" .. PARQUET .. "')"

------------------------------------------------------------------------------
-- run the decoder
------------------------------------------------------------------------------
local cmd = string.format("%s -r %s -o %s -t 0 2>/dev/null", DECODER, PCAP, PARQUET)
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

------------------------------------------------------------------------------
-- checks: { name, sql, expected }
------------------------------------------------------------------------------
local checks =
{
	{ "row count",
	  "SELECT count(*) FROM " .. TBL,
	  "23" },

	{ "message sequence and order",
	  "SELECT string_agg(msgType, '' ORDER BY moldSeqNo) FROM " .. TBL,
	  "SRHYLVWKJhAFECXDUPQBINO" },

	{ "mold session on every row",
	  "SELECT count(*) FROM " .. TBL .. " WHERE moldSession = 'TEST0001'",
	  "23" },

	{ "itch timestamp on every row",
	  "SELECT count(*) FROM " .. TBL .. " WHERE timestampNS = 34200000000000",
	  "23" },

	{ "S system event",
	  "SELECT eventCode || '|' || stockLocate::VARCHAR FROM " .. TBL .. " WHERE msgType = 'S'",
	  "Q|0" },

	{ "R stock directory",
	  "SELECT stock || '|' || marketCategory || '|' || financialStatusIndicator || '|' || roundLotSize::VARCHAR || '|' || roundLotsOnly || '|' || issueClassification || '|' || " .. N("issueSubType") .. " || '|' || authenticity || '|' || luldReferencePriceTier || '|' || etpLeverageFactor::VARCHAR FROM " .. TBL .. " WHERE msgType = 'R'",
	  "AAPL|Q|N|100|N|C|NULL|P|1|1" },

	{ "H trading action",
	  "SELECT stock || '|' || tradingState || '|' || " .. N("tradingActionReason") .. " FROM " .. TBL .. " WHERE msgType = 'H'",
	  "AAPL|T|NULL" },

	{ "Y reg sho",
	  "SELECT stock || '|' || regSHOAction FROM " .. TBL .. " WHERE msgType = 'Y'",
	  "AAPL|0" },

	{ "L market participant position",
	  "SELECT mpid || '|' || stock || '|' || primaryMarketMaker || '|' || marketMakerMode || '|' || marketParticipantState FROM " .. TBL .. " WHERE msgType = 'L'",
	  "NSDQ|AAPL|Y|N|A" },

	{ "V mwcb decline levels (price8)",
	  "SELECT mwcbLevel1::VARCHAR || '|' || mwcbLevel2::VARCHAR || '|' || mwcbLevel3::VARCHAR FROM " .. TBL .. " WHERE msgType = 'V'",
	  "190.00000000|180.00000000|165.00000000" },

	{ "W mwcb status",
	  "SELECT mwcbBreachedLevel FROM " .. TBL .. " WHERE msgType = 'W'",
	  "1" },

	{ "K ipo quoting period",
	  "SELECT stock || '|' || ipoQuotationReleaseTime::VARCHAR || '|' || ipoQuotationReleaseQualifier || '|' || ipoPrice::VARCHAR FROM " .. TBL .. " WHERE msgType = 'K'",
	  "NEWCO|34200|A|25.0000" },

	{ "J luld auction collar",
	  "SELECT stock || '|' || auctionCollarReferencePrice::VARCHAR || '|' || upperAuctionCollarPrice::VARCHAR || '|' || lowerAuctionCollarPrice::VARCHAR || '|' || auctionCollarExtension::VARCHAR FROM " .. TBL .. " WHERE msgType = 'J'",
	  "AAPL|150.0000|165.0000|135.0000|0" },

	{ "h operational halt",
	  "SELECT stock || '|' || marketCode || '|' || operationalHaltAction FROM " .. TBL .. " WHERE msgType = 'h'",
	  "AAPL|Q|T" },

	{ "A add order",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || buySellIndicator || '|' || shares::VARCHAR || '|' || stock || '|' || price::VARCHAR FROM " .. TBL .. " WHERE msgType = 'A'",
	  "1001|B|100|AAPL|150.1234" },

	{ "F add order mpid",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || buySellIndicator || '|' || shares::VARCHAR || '|' || stock || '|' || price::VARCHAR || '|' || attribution FROM " .. TBL .. " WHERE msgType = 'F'",
	  "1002|S|200|AAPL|150.9999|JPMS" },

	{ "E order executed",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || executedShares::VARCHAR || '|' || matchNumber::VARCHAR FROM " .. TBL .. " WHERE msgType = 'E'",
	  "1001|50|900001" },

	{ "C order executed with price",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || executedShares::VARCHAR || '|' || matchNumber::VARCHAR || '|' || printable || '|' || executionPrice::VARCHAR FROM " .. TBL .. " WHERE msgType = 'C'",
	  "1001|25|900002|Y|150.1000" },

	{ "X order cancel",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || cancelledShares::VARCHAR FROM " .. TBL .. " WHERE msgType = 'X'",
	  "1002|75" },

	{ "D order delete",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || " .. N("shares") .. " FROM " .. TBL .. " WHERE msgType = 'D'",
	  "1002|NULL" },

	{ "U order replace",
	  "SELECT originalOrderReferenceNumber::VARCHAR || '|' || newOrderReferenceNumber::VARCHAR || '|' || shares::VARCHAR || '|' || price::VARCHAR FROM " .. TBL .. " WHERE msgType = 'U'",
	  "1001|1003|25|150.2000" },

	{ "P trade non cross",
	  "SELECT orderReferenceNumber::VARCHAR || '|' || buySellIndicator || '|' || shares::VARCHAR || '|' || stock || '|' || price::VARCHAR || '|' || matchNumber::VARCHAR FROM " .. TBL .. " WHERE msgType = 'P'",
	  "0|B|300|AAPL|150.0000|900003" },

	{ "Q cross trade",
	  "SELECT shares::VARCHAR || '|' || stock || '|' || crossPrice::VARCHAR || '|' || matchNumber::VARCHAR || '|' || crossType FROM " .. TBL .. " WHERE msgType = 'Q'",
	  "50000|AAPL|150.5000|900004|O" },

	{ "B broken trade",
	  "SELECT matchNumber::VARCHAR FROM " .. TBL .. " WHERE msgType = 'B'",
	  "900002" },

	{ "I noii",
	  "SELECT pairedShares::VARCHAR || '|' || imbalanceShares::VARCHAR || '|' || imbalanceDirection || '|' || stock || '|' || farPrice::VARCHAR || '|' || nearPrice::VARCHAR || '|' || currentReferencePrice::VARCHAR || '|' || crossType || '|' || priceVariationIndicator FROM " .. TBL .. " WHERE msgType = 'I'",
	  "10000|500|B|AAPL|150.4000|150.5000|150.5000|O|L" },

	{ "N rpii",
	  "SELECT stock || '|' || interestFlag FROM " .. TBL .. " WHERE msgType = 'N'",
	  "AAPL|A" },

	{ "O direct listing capital raise",
	  "SELECT stock || '|' || openEligibilityStatus || '|' || minimumAllowablePrice::VARCHAR || '|' || maximumAllowablePrice::VARCHAR || '|' || nearExecutionPrice::VARCHAR || '|' || nearExecutionTimeNS::VARCHAR || '|' || lowerPriceRangeCollar::VARCHAR || '|' || upperPriceRangeCollar::VARCHAR FROM " .. TBL .. " WHERE msgType = 'O'",
	  "NEWCO|Y|20.0000|45.0000|30.0000|34200000000000|27.0000|33.0000" },
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
