------------------------------------------------------------------------------
--
-- validate_synthetic.lua
--
-- Runs the fmadio_markets decoder (-p fix42) over the generated validation
-- pcap and checks the parquet output field values against the known values
-- from gen_pcap.lua, using the duckdb CLI. Also verifies that -p auto never
-- claims the FIX flows (noAutoDetect).
--
-- usage: luajit validate_synthetic.lua [decoder] [pcap] [parquet]
--
------------------------------------------------------------------------------

local DECODER = arg[1] or "../../../src/fmadio_markets"
local PCAP    = arg[2] or "fix42_test.pcap"
local PARQUET = arg[3] or "fix42_test.parq"

local TBL = "read_parquet('" .. PARQUET .. "')"

------------------------------------------------------------------------------
-- run the decoder
------------------------------------------------------------------------------
local cmd = string.format("%s -r %s -o %s -p fix42 -t 0 2>/dev/null", DECODER, PCAP, PARQUET)
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

------------------------------------------------------------------------------
-- checks: { name, sql, expected }
------------------------------------------------------------------------------
local checks =
{
	{ "row count (6 client + 6 server + 1 mid stream)",
	  "SELECT count(*) FROM " .. TBL,
	  "13" },

	{ "client message type sequence (Logon, 3x NewOrderSingle, Cancel, Logout)",
	  "SELECT string_agg(fix_35, '' ORDER BY fix_34) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1'",
	  "ADDDF5" },

	{ "server message type sequence (Logon, ER, ER, Heartbeat, ER, Reject)",
	  "SELECT string_agg(fix_35, '' ORDER BY fix_34) FROM " .. TBL .. " WHERE fix_49 = 'BROKER'",
	  "A88083" },

	{ "capture layer: every row is TCP with the server on one side",
	  "SELECT count(*) FROM " .. TBL .. " WHERE frame_ipProto = 6 AND (frame_ipDst = '10.0.0.5' OR frame_ipSrc = '10.0.0.5')",
	  "13" },

	{ "BeginString / BodyLength / CheckSum stored on every row",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_8 = 'FIX.4.2' AND fix_9 > 0 AND fix_10 IS NOT NULL",
	  "13" },

	{ "split message reassembled (NewOrderSingle across two TCP segments)",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 2 AND fix_11 = 'ORD0001' AND fix_55 = '7203' AND fix_54 = '1' AND fix_38 = 100 AND fix_40 = '2' AND fix_44 = 1234.5 AND fix_59 = '0'",
	  "1" },

	{ "split message row carries the completing packet timestamp",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 2 AND frame_ts = 1758762006000000000",
	  "1" },

	{ "two messages packed into one segment share the packet timestamp",
	  "SELECT count(DISTINCT frame_ts) FROM " .. TBL .. " WHERE fix_49 = 'BROKER' AND fix_34 IN (2, 3)",
	  "1" },

	{ "execution report fill values (LastShares/LastPx/CumQty/AvgPx doubles)",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'BROKER' AND fix_34 = 3 AND fix_17 = 'E2' AND fix_150 = '2' AND fix_39 = '2' AND fix_32 = 100 AND fix_31 = 1234.5 AND fix_14 = 100 AND fix_6 = 1234.5 AND fix_151 = 0",
	  "1" },

	{ "LENGTH/DATA pair: RawDataLength BIGINT + RawData with sanitized SOH",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 3 AND fix_95 = 5 AND fix_96 = 'AB.CD'",
	  "1" },

	{ "repeating group: first occurrence wins, duplicate counted",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 4 AND fix_386 = 2 AND fix_336 = 'X' AND hdr_dupTagCount = 1",
	  "1" },

	{ "custom tag 847 stored, tag 5001 dropped and counted",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 4 AND fix_847 = 'XYZ' AND hdr_overflowTagCount = 1",
	  "1" },

	{ "out of order segment reassembled (cancel ER after heartbeat)",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'BROKER' AND fix_34 = 5 AND fix_150 = '4' AND fix_41 = 'ORD0001' AND fix_11 = 'ORD0004'",
	  "1" },

	{ "corrupted checksum row emitted and flagged",
	  "SELECT count(*) FROM " .. TBL .. " WHERE hdr_checksumValid = 0 AND fix_49 = 'BROKER' AND fix_34 = 6 AND fix_58 = 'BADCHECKSUM'",
	  "1" },

	{ "every other row has a valid checksum",
	  "SELECT count(*) FROM " .. TBL .. " WHERE hdr_checksumValid = 1",
	  "12" },

	{ "mid stream capture start resyncs onto the next 8=FIX boundary",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT2' AND fix_35 = '0' AND fix_34 = 1 AND frame_portSrc = 52000",
	  "1" },

	{ "non FIX TCP flow emits no rows",
	  "SELECT count(*) FROM " .. TBL .. " WHERE frame_portSrc = 53000",
	  "0" },

	{ "timestamps stored verbatim as VARCHAR",
	  "SELECT fix_52 FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 1",
	  "20250925-01:00:00" },

	{ "cancel request token chain",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_49 = 'CLIENT1' AND fix_34 = 5 AND fix_35 = 'F' AND fix_41 = 'ORD0001' AND fix_11 = 'ORD0004'",
	  "1" },

	{ "logon fields (EncryptMethod BIGINT, HeartBtInt BIGINT)",
	  "SELECT count(*) FROM " .. TBL .. " WHERE fix_35 = 'A' AND fix_98 = 0 AND fix_108 = 30",
	  "2" },
}

local pass = 0
local fail = 0
for _, c in ipairs(checks) do
	local got = query(c[2])
	if got == c[3] then
		pass = pass + 1
		print(string.format("PASS  %s", c[1]))
	else
		fail = fail + 1
		print(string.format("FAIL  %s\n      expected [%s]\n      got      [%s]", c[1], c[3], got))
	end
end

------------------------------------------------------------------------------
-- negative: -p auto must never claim the FIX flows (noAutoDetect), so no
-- parquet output is written at all
------------------------------------------------------------------------------
local AUTO_PARQUET = PARQUET .. ".auto"
os.remove(AUTO_PARQUET)
os.execute(string.format("%s -r %s -o %s -t 0 2>/dev/null", DECODER, PCAP, AUTO_PARQUET))
local f = io.open(AUTO_PARQUET, "r")
if f == nil then
	pass = pass + 1
	print("PASS  -p auto does not claim FIX flows (no output written)")
else
	f:close()
	os.remove(AUTO_PARQUET)
	fail = fail + 1
	print("FAIL  -p auto claimed the FIX flows (output written)")
end

print(string.format("\n%d/%d checks passed", pass, pass + fail))
os.exit(fail == 0 and 0 or 1)
