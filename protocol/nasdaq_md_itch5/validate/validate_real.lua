------------------------------------------------------------------------------
--
-- validate_real.lua
--
-- Real data validation of the ITCH 5.0 decoder. Runs the full pipeline:
--
--   1. decode the production pcap (zstd compressed, streamed via zstdcat
--      into the decoder stdin) writing a temporary parquet into this
--      directory
--   2. join every decoded message against the 3rd party mdgap seqno
--      reference csv on mold sequence number
--   3. check: every parquet message exists in the reference, every matched
--      message has an identical pcap timestamp, and any reference-only rows
--      match the MoldUDP64 End of Session artifact signature (the 3rd party
--      tool counts the 0xFFFF sentinel as 65535 real messages from a single
--      packet / single pcap timestamp)
--
-- usage: luajit validate_real.lua <decoder> <pcap[.zst]> <mdgap.csv[.zst]> <out.parquet>
--
------------------------------------------------------------------------------

local DECODER = arg[1] or "../../../src/fmadio_markets"
local PCAP    = arg[2] or "../../../data/protocol/nasdaq_md_itch5/ny4-xnas-tvitch-20230822.pcap.zst"
local CSV     = arg[3] or "../../../data/protocol/nasdaq_md_itch5/ny4-xnas-tvitch-20230822.pcap.mdgap.seqno.csv.zst"
local PARQUET = arg[4] or "ny4-xnas-tvitch-20230822.parquet"

print(string.format("decoder : %s", DECODER))
print(string.format("pcap    : %s", PCAP))
print(string.format("csv     : %s", CSV))
print(string.format("parquet : %s", PARQUET))

------------------------------------------------------------------------------
-- step 1: decode the pcap into a parquet file
------------------------------------------------------------------------------
os.remove(PARQUET)

local cmd
if PCAP:match("%.zstd?$") then
	cmd = string.format("zstdcat %s | %s -o %s", PCAP, DECODER, PARQUET)
else
	cmd = string.format("%s -r %s -o %s", DECODER, PCAP, PARQUET)
end

print("\n[1/2] decoding: " .. cmd .. "\n")
local ok = os.execute(cmd)
if (ok ~= 0 and ok ~= true) or not io.open(PARQUET, "r") then
	print("FAIL: decoder did not produce " .. PARQUET)
	os.exit(1)
end

------------------------------------------------------------------------------
-- duckdb query helper: returns csv output, trimmed
------------------------------------------------------------------------------
local function query(sql)
	local p = assert(io.popen("duckdb -csv -noheader -c \"" .. sql .. "\" 2>&1"))
	local out = p:read("*a")
	p:close()
	return (out:gsub("%s+$", ""))
end

local function split(line)
	local f = {}
	for v in line:gmatch("[^,]+") do
		f[#f + 1] = v
	end
	return f
end

------------------------------------------------------------------------------
-- step 2: counts, both direction anti joins, timestamp mismatches
------------------------------------------------------------------------------
print("[2/2] comparing against reference (large join, this can take minutes)...\n")

local sql = string.format([[
WITH c AS (SELECT column0 AS ts, column5 AS seq FROM read_csv('%s', header=false)),
     p AS (SELECT pcapTS, moldSeqNo AS seq FROM '%s')
SELECT
  (SELECT count(*) FROM c),
  (SELECT count(*) FROM p),
  (SELECT count(*) FROM p LEFT JOIN c USING(seq) WHERE c.seq IS NULL),
  (SELECT count(*) FROM c JOIN p USING(seq) WHERE c.ts != p.pcapTS),
  (SELECT count(*) FROM c LEFT JOIN p USING(seq) WHERE p.seq IS NULL)
]], CSV, PARQUET)

local r = split(query(sql))
local csvRows    = tonumber(r[1])
local parqRows   = tonumber(r[2])
local parqOnly   = tonumber(r[3])
local tsMismatch = tonumber(r[4])
local csvOnly    = tonumber(r[5])

if not csvRows then
	print("FAIL  duckdb comparison query failed:")
	print(query(sql))
	os.exit(1)
end

print(string.format("reference rows : %d", csvRows))
print(string.format("parquet rows   : %d", parqRows))

local pass, fail = 0, 0
local function check(name, ok2, detail)
	if ok2 then
		pass = pass + 1
		print(string.format("PASS  %s", name))
	else
		fail = fail + 1
		print(string.format("FAIL  %s (%s)", name, detail))
	end
end

check("all parquet messages exist in reference", parqOnly == 0,
	string.format("%d parquet-only rows", parqOnly))
check("all matched timestamps identical", tsMismatch == 0,
	string.format("%d timestamp mismatches", tsMismatch))

------------------------------------------------------------------------------
-- explain reference-only rows: End of Session packets only
------------------------------------------------------------------------------
if csvOnly == 0 then
	check("no unexplained reference-only rows", true, "")
else
	local sql2 = string.format([[
WITH c AS (SELECT column0 AS ts, column5 AS seq FROM read_csv('%s', header=false)),
     p AS (SELECT moldSeqNo AS seq FROM '%s'),
     miss AS (SELECT c.ts, c.seq FROM c LEFT JOIN p USING(seq) WHERE p.seq IS NULL)
SELECT count(*), count(DISTINCT ts), max(seq) - min(seq) + 1 FROM miss
]], CSV, PARQUET)

	local m = split(query(sql2))
	local missCnt    = tonumber(m[1])
	local distinctTS = tonumber(m[2])
	local span       = tonumber(m[3])

	print(string.format("      reference-only rows: %d, distinct pcap ts: %d, seq span: %d",
		missCnt, distinctTS, span))

	-- each End of Session packet contributes 65535 phantom rows from ONE
	-- pcap timestamp in ONE contiguous seq block
	local eosOK = (missCnt == distinctTS * 65535) and (span == missCnt or distinctTS > 1)
	check("reference-only rows are End of Session artifacts (3rd party 0xFFFF bug)",
		eosOK,
		string.format("%d rows / %d packets do not match the 65535-per-EOS-packet signature",
			missCnt, distinctTS))
end

print(string.format("\n%d/%d checks passed", pass, pass + fail))
os.exit(fail == 0 and 0 or 1)
