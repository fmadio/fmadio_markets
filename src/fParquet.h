#pragma once

//------------------------------------------------------------------------------
//
// fParquet.h
//
// Parquet output context. The context is passed into ProcessPacket and down
// to the individual protocol decoders, which create their own protocol
// specific schema and append decoded messages via the parq.h writer API.
//
// The writer backend state is private to the parq.h backend selected at
// compile time in the Makefile (src/parq_*.c); nothing outside the backend
// touches it.
//
//------------------------------------------------------------------------------

typedef struct
{
	const char*	tableName;	// protocol table name, set by parquetSchemaCreate
	void*		backend;	// writer backend private state

} Parquet_t;
