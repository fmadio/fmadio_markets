#pragma once

//------------------------------------------------------------------------------
//
// parq.h
//
// parquet output management interface: writer open/close, output of the
// protocol table as parquet on close, -t time based output rotation, and the
// schema / row append API used by the protocol decoders. the decoders never
// touch the writer backend directly, everything goes through this interface.
//
// the implementation backend (src/parq_*.c) is selected at compile time in
// the Makefile. the interface makes no assumption about the writer library:
// schemas are declared as a column table (not SQL) so a backend may build
// DDL or feed a native schema API; rows are appended strictly one column at
// a time in schema order, which maps onto both row appender and column
// cursor style writers; output file names are resolved inside the backend
// because some writers need the path at open while others need it at close.
//
//------------------------------------------------------------------------------

#include "fTypes.h"
#include "fParquet.h"

//------------------------------------------------------------------------------
// schema declaration: a flat table of (column name, type). the backend maps
// these onto its writer's native types; a backend without decimal support
// writes the DECIMAL types as parquet DOUBLE (the value is appended with
// parquetAppendDouble either way, only the logical column type differs).
// every column is nullable
//
// schema declaration: a flat table of (column name, type). backend type
// mapping:
//                           duckdb          other 
//   PARQUET_TYPE_U8         UTINYINT        PQ_TYPE_U8
//   PARQUET_TYPE_U16        USMALLINT       PQ_TYPE_U16
//   PARQUET_TYPE_U32        UINTEGER        PQ_TYPE_U32
//   PARQUET_TYPE_U64        UBIGINT         PQ_TYPE_U64
//   PARQUET_TYPE_S32        INTEGER         PQ_TYPE_I32
//   PARQUET_TYPE_S64        BIGINT          PQ_TYPE_I64
//   PARQUET_TYPE_DOUBLE     DOUBLE          PQ_TYPE_F64
//   PARQUET_TYPE_STRING     VARCHAR         PQ_TYPE_STRING
//   PARQUET_TYPE_DECIMAL16_4 DECIMAL(16,4)  PQ_TYPE_F64 (no decimal support)
//   PARQUET_TYPE_DECIMAL20_8 DECIMAL(20,8)  PQ_TYPE_F64 (no decimal support)
//

typedef enum
{
	PARQUET_TYPE_U8 = 0,
	PARQUET_TYPE_U16,
	PARQUET_TYPE_U32,
	PARQUET_TYPE_U64,
	PARQUET_TYPE_S32,
	PARQUET_TYPE_S64,
	PARQUET_TYPE_DOUBLE,
	PARQUET_TYPE_STRING,
	PARQUET_TYPE_DECIMAL16_4,
	PARQUET_TYPE_DECIMAL20_8,

} ParquetType_t;

typedef struct
{
	const char*		name;		// column name
	ParquetType_t	type;

} ParquetColumn_t;

//------------------------------------------------------------------------------
// output lifecycle (main.c)

// default output file name when -o is not given. single source of truth:
// used by the main.c arg default / usage text and as the backend fallback
#define PARQUET_OUTPUT_DEFAULT	"fmadio_markets.parq"

// recreates the active protocol schema + appender on a fresh writer after a
// rotation (main.c protocolSchemaCreate)
typedef bool (*ParquetSchemaCreate_f)(Parquet_t* pq);

// set the output file name, rotation period in ns of pcap time (0 = no
// rotation, single file) and the schema recreate callback, once at startup
void parquetConfig(const char* outputName, u64 rotatePeriodNS, ParquetSchemaCreate_f schemaCreate);

// open the writer backend. the protocol specific schema is created by the
// protocol decoder (parquetSchemaCreate) after this call
bool parquetOpen(Parquet_t* pq);

// per packet rotation check: flush the current window and start a new file
// on every rotation period boundary in pcap time. rotation waits for a
// protocol to be selected (pq->tableName set), until then only the window
// index is tracked
void parquetRotateCheck(Parquet_t* pq, u64 ts);

// final flush at end of input, rotation aware file naming
void parquetFinalClose(Parquet_t* pq);

// number of parquet files written
u64 parquetFileTotal(void);

//------------------------------------------------------------------------------
// protocol decoder writer API

// create the protocol table from the column table and set pq->tableName.
// called by the Protocol_*SchemaCreate functions
bool parquetSchemaCreate(Parquet_t* pq, const char* tableName, const ParquetColumn_t* columns, u32 columnCount);

// write one row: parquetRowBegin, one parquetAppend* per column in exact
// schema order, parquetRowEnd. parquetRowEnd returns false (and prints the
// backend error) on append failure
void parquetRowBegin(Parquet_t* pq);
bool parquetRowEnd(Parquet_t* pq);

void parquetAppendU8(Parquet_t* pq, u8 v);
void parquetAppendU16(Parquet_t* pq, u16 v);
void parquetAppendU32(Parquet_t* pq, u32 v);
void parquetAppendU64(Parquet_t* pq, u64 v);
void parquetAppendS32(Parquet_t* pq, s32 v);
void parquetAppendS64(Parquet_t* pq, s64 v);
void parquetAppendDouble(Parquet_t* pq, double v);
void parquetAppendStr(Parquet_t* pq, const char* s);	// NULL or empty string appends a NULL column
void parquetAppendNull(Parquet_t* pq);
