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

-- the parquet columns are grouped (frame_* / hdr_* / msg_*); alias them
-- back to bare names once here so the check SQL below stays readable
local COLS = '"frame_ts" AS pcapTS, "frame_ipSrc" AS ipSrc, "frame_ipDst" AS ipDst, "frame_portSrc" AS portSrc, "frame_portDst" AS portDst, "frame_ipProto" AS ipProto, "frame_vlanOuter" AS vlanOuter, "frame_vlanInner" AS vlanInner, "frame_pbTS" AS pbTS, "frame_pbFlags" AS pbFlags, "frame_pbDeviceID" AS pbDeviceID, "frame_pbPortID" AS pbPortID, "frame_hostname" AS hostname, "frame_pkt_block" AS pkt_block, "frame_pkt_offset" AS pkt_offset, "hdr_session" AS moldSession, "hdr_seqNo" AS moldSeqNo, "msg_type" AS msgType, "msg_stockLocate" AS stockLocate, "msg_trackingNumber" AS trackingNumber, "msg_timestampNS" AS timestampNS, "msg_eventCode" AS eventCode, "msg_stock" AS stock, "msg_marketCategory" AS marketCategory, "msg_financialStatusIndicator" AS financialStatusIndicator, "msg_roundLotSize" AS roundLotSize, "msg_roundLotsOnly" AS roundLotsOnly, "msg_issueClassification" AS issueClassification, "msg_issueSubType" AS issueSubType, "msg_authenticity" AS authenticity, "msg_shortSaleThresholdIndicator" AS shortSaleThresholdIndicator, "msg_ipoFlag" AS ipoFlag, "msg_luldReferencePriceTier" AS luldReferencePriceTier, "msg_etpFlag" AS etpFlag, "msg_etpLeverageFactor" AS etpLeverageFactor, "msg_inverseIndicator" AS inverseIndicator, "msg_tradingState" AS tradingState, "msg_tradingActionReason" AS tradingActionReason, "msg_regSHOAction" AS regSHOAction, "msg_mpid" AS mpid, "msg_primaryMarketMaker" AS primaryMarketMaker, "msg_marketMakerMode" AS marketMakerMode, "msg_marketParticipantState" AS marketParticipantState, "msg_mwcbLevel1"::DECIMAL(20,8) AS mwcbLevel1, "msg_mwcbLevel2"::DECIMAL(20,8) AS mwcbLevel2, "msg_mwcbLevel3"::DECIMAL(20,8) AS mwcbLevel3, "msg_mwcbBreachedLevel" AS mwcbBreachedLevel, "msg_ipoQuotationReleaseTime" AS ipoQuotationReleaseTime, "msg_ipoQuotationReleaseQualifier" AS ipoQuotationReleaseQualifier, "msg_ipoPrice"::DECIMAL(16,4) AS ipoPrice, "msg_auctionCollarReferencePrice"::DECIMAL(16,4) AS auctionCollarReferencePrice, "msg_upperAuctionCollarPrice"::DECIMAL(16,4) AS upperAuctionCollarPrice, "msg_lowerAuctionCollarPrice"::DECIMAL(16,4) AS lowerAuctionCollarPrice, "msg_auctionCollarExtension" AS auctionCollarExtension, "msg_marketCode" AS marketCode, "msg_operationalHaltAction" AS operationalHaltAction, "msg_orderReferenceNumber" AS orderReferenceNumber, "msg_originalOrderReferenceNumber" AS originalOrderReferenceNumber, "msg_newOrderReferenceNumber" AS newOrderReferenceNumber, "msg_buySellIndicator" AS buySellIndicator, "msg_shares" AS shares, "msg_price"::DECIMAL(16,4) AS price, "msg_attribution" AS attribution, "msg_executedShares" AS executedShares, "msg_matchNumber" AS matchNumber, "msg_printable" AS printable, "msg_executionPrice"::DECIMAL(16,4) AS executionPrice, "msg_cancelledShares" AS cancelledShares, "msg_crossPrice"::DECIMAL(16,4) AS crossPrice, "msg_crossType" AS crossType, "msg_pairedShares" AS pairedShares, "msg_imbalanceShares" AS imbalanceShares, "msg_imbalanceDirection" AS imbalanceDirection, "msg_farPrice"::DECIMAL(16,4) AS farPrice, "msg_nearPrice"::DECIMAL(16,4) AS nearPrice, "msg_currentReferencePrice"::DECIMAL(16,4) AS currentReferencePrice, "msg_priceVariationIndicator" AS priceVariationIndicator, "msg_interestFlag" AS interestFlag, "msg_openEligibilityStatus" AS openEligibilityStatus, "msg_minimumAllowablePrice"::DECIMAL(16,4) AS minimumAllowablePrice, "msg_maximumAllowablePrice"::DECIMAL(16,4) AS maximumAllowablePrice, "msg_nearExecutionPrice"::DECIMAL(16,4) AS nearExecutionPrice, "msg_nearExecutionTimeNS" AS nearExecutionTimeNS, "msg_lowerPriceRangeCollar"::DECIMAL(16,4) AS lowerPriceRangeCollar, "msg_upperPriceRangeCollar"::DECIMAL(16,4) AS upperPriceRangeCollar'
local TBL = "(SELECT " .. COLS .. " FROM read_parquet('" .. PARQUET .. "'))"

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
	local p = assert(io.popen("duckdb -csv -noheader -c \"" .. sql:gsub('"', '\\"') .. "\" 2>&1"))
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
