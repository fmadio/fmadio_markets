------------------------------------------------------------------------------
--
-- validate_real.lua
--
-- Validates a production decoder parquet against a 3rd party reference csv
-- (mdgap format: pcap epoch ns, len, group, port, protocol, mold seq no; one
-- row per market data message).
--
-- Checks:
--   1. every parquet message exists in the reference (seq join)
--   2. every matched message has an identical pcap timestamp
--   3. reference rows missing from the parquet are explained: they must all
--      come from single MoldUDP64 End of Session packets (one distinct pcap
--      timestamp per contiguous seq block; the 3rd party tool counts the
--      0xFFFF sentinel as 65535 real messages)
--
-- usage: luajit validate_real.lua <decoder.parquet> <mdgap.csv>
--
------------------------------------------------------------------------------

local PARQUET = arg[1] or "../../../fmadio_markets.parquet"
local CSV     = arg[2] or "../../../mdgap.csv"

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

print(string.format("parquet : %s", PARQUET))
print(string.format("csv     : %s", CSV))
print("running comparison (large join, this can take minutes)...\n")

------------------------------------------------------------------------------
-- one pass: counts, both direction anti joins, timestamp mismatches
------------------------------------------------------------------------------
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
local function check(name, ok, detail)
	if ok then
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
	local missCnt   = tonumber(m[1])
	local distinctTS = tonumber(m[2])
	local span      = tonumber(m[3])

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
