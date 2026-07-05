-- Trades grouped into 1 minute buckets
--
-- Trade messages: msgType 'P' (Trade non-cross, price) and 'Q' (Cross Trade, crossPrice).
-- pcapTS is UBIGINT nanoseconds since epoch; make_timestamp() takes microseconds as BIGINT.
--
-- Usage: duckdb -c ".read protocol/nasdaq_md_itch5/timeseries_trade.sql"
-- (run from the repo root, or adjust the parquet path)

SELECT
    time_bucket(INTERVAL 1 MINUTE, make_timestamp((pcapTS // 1000)::BIGINT)) AS minute,
    count(*)                                                                 AS trades,
    sum(shares)                                                              AS totalShares,
    sum(shares * coalesce(price, crossPrice))                                AS notional
FROM read_parquet('./*.parq')
WHERE msgType IN ('P', 'Q')
GROUP BY 1
ORDER BY 1;
