-- Histogram of ITCH message types
--
-- One row per msgType: count, percentage of all messages, and an ASCII bar
-- scaled so the most frequent type gets 50 characters.
--
-- Usage: duckdb -f process/histogram_msgtype.sql

SELECT
	msgType,
	format('{:,}', count(*))                                                   AS msgCount,
	round(100.0 * count(*) / sum(count(*)) OVER (), 2)                         AS pct,
	repeat('#', greatest(1, (50.0 * count(*) / max(count(*)) OVER ())::INT))   AS bar
FROM read_parquet('*.parq')
GROUP BY msgType
ORDER BY count(*) DESC;
