#pragma once

//------------------------------------------------------------------------------
//
// fParquet.h
//
// Parquet output context via libduckdb. The decoder appends rows into an
// in-memory duckdb table and writes the table out as a parquet file on
// close. The context is passed into ProcessPacket and down to the
// individual protocol decoders, which create their own protocol specific
// schema and append decoded messages via the appender.
//
//------------------------------------------------------------------------------

#include <duckdb.h>

typedef struct
{
	duckdb_database		db;			// in-memory duckdb instance
	duckdb_connection	con;		// connection used for DDL and COPY
	duckdb_appender		appender;	// fast row appender into the protocol table
	const char*			tableName;	// protocol table name, set by the protocol schema create

} Parquet_t;
