-- Trades and order book activity grouped into 1 minute buckets, JSON output via COPY
--
-- Trade messages: msgType 'P' (Trade non-cross, price) and 'Q' (Cross Trade, crossPrice).
-- Order lifecycle:
--   created  = 'A' (Add Order) + 'F' (Add Order with MPID)
--   modified = 'U' (Order Replace) + 'X' (Order Cancel, partial shares removed)
--   deleted  = 'D' (Order Delete)
-- pcapTS is UBIGINT nanoseconds since epoch; make_timestamp() takes microseconds as BIGINT.
--
-- Writes newline-delimited JSON (one object per row) to stdout.
-- Add ", ARRAY true" to the options for a single JSON array instead.
--
-- Usage: duckdb -f process/timeseries_order_trade_1m.sql

COPY
(
	SELECT
		time_bucket(INTERVAL 1 HOUR, make_timestamp((pcapTS // 1000)::BIGINT))          AS timeBin,
		count(*) FILTER (WHERE msgType IN ('A', 'F'))                                     AS ordersCreated,
		count(*) FILTER (WHERE msgType IN ('U', 'X'))                                     AS ordersModified,
		count(*) FILTER (WHERE msgType = 'D')                                             AS ordersDeleted,
		count(*) FILTER (WHERE msgType IN ('P', 'Q'))                                     AS trades,
		sum(shares)               FILTER (WHERE msgType IN ('P', 'Q'))                    AS tradeShares,
		sum(shares * coalesce(price, crossPrice)) FILTER (WHERE msgType IN ('P', 'Q'))    AS tradeNotional
	FROM read_parquet('*.parq')
	WHERE msgType IN ('A', 'F', 'U', 'X', 'D', 'P', 'Q')
	GROUP BY 1
	ORDER BY 1
)
TO '/dev/stdout' (FORMAT JSON);
