//------------------------------------------------------------------------------
//
// parq_duckdb.c
//
// libduckdb backend of the parq.h parquet output interface: duckdb instance
// open/close, COPY of the protocol table to parquet on close, -t time based
// output rotation, and the schema / row append API used by the protocol
// decoders. all duckdb usage in the project lives in this file.
//
// the parquet writer backend is selected at compile time in the Makefile
// (backend block, src/parq_*.c); every backend implements the same parq.h
// interface.
//
// libduckdb buffers the entire table in memory until the COPY on close, so
// with rotation enabled the output is flushed and a new parquet file started
// on every rotation period boundary (pcap time). rotated files are named
// <stem>_<YYYYMMDD_HHMMSS UTC of window start><ext>.
//
//------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <duckdb.h>

#include "fTypes.h"
#include "fParquet.h"
#include "parq.h"

// backend private state hanging off Parquet_t.backend
typedef struct
{
	duckdb_database		db;			// in-memory duckdb instance
	duckdb_connection	con;		// connection used for DDL and COPY
	duckdb_appender		appender;	// fast row appender into the protocol table

} ParquetDuckDB_t;

#define BACKEND(pq)		((ParquetDuckDB_t*)(pq)->backend)

static const char*	s_outputName = PARQUET_OUTPUT_DEFAULT;		// set by parquetConfig; the backend owns naming (rotation windows, close)
static u64			s_rotatePeriodNS = 0;						// rotation period in nanoseconds, 0 = no rotation
static u64			s_rotateBucket = 0;							// current rotation window index (pcap ts / period)
static bool			s_rotateBucketValid = false;				// window index is valid once the first packet is seen
static u64			s_totalFile = 0;							// parquet files written

static ParquetSchemaCreate_f s_schemaCreate = NULL;				// recreates the protocol schema after a rotation

//------------------------------------------------------------------------------
// parquetConfig: set the output name, rotation period and schema recreate
// callback, once at startup
//------------------------------------------------------------------------------
void parquetConfig(const char* outputName, u64 rotatePeriodNS, ParquetSchemaCreate_f schemaCreate)
{
	s_outputName = outputName;
	s_rotatePeriodNS = rotatePeriodNS;
	s_schemaCreate = schemaCreate;
}

//------------------------------------------------------------------------------
// parquetOpen: open the in-memory duckdb instance. The protocol specific
// schema and appender are created by the protocol decoder (e.g.
// Protocol_ITCH5SchemaCreate) after this call. The output file name is only
// needed on close, when the buffered table is written out.
//------------------------------------------------------------------------------
bool parquetOpen(Parquet_t* pq)
{
	memset(pq, 0, sizeof(Parquet_t));

	ParquetDuckDB_t* be = calloc(1, sizeof(ParquetDuckDB_t));
	if (!be)
	{
		fprintf(stderr, "parquet: failed to allocate backend state\n");
		return false;
	}
	pq->backend = be;

	if (duckdb_open(NULL, &be->db) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to open duckdb\n");
		return false;
	}
	if (duckdb_connect(be->db, &be->con) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to connect to duckdb\n");
		return false;
	}

	return true;
}

//------------------------------------------------------------------------------
// parquetClose: flush the appender and write the protocol table out as parquet
//------------------------------------------------------------------------------
static void parquetClose(Parquet_t* pq, const char* fileName)
{
	ParquetDuckDB_t* be = BACKEND(pq);

	if (be->appender)
	{
		duckdb_appender_close(be->appender);
		duckdb_appender_destroy(&be->appender);
	}

	// no schema was ever created (autodetect found no protocol traffic)
	if (pq->tableName == NULL)
	{
		fprintf(stderr, "parquet: no protocol detected, nothing written to [%s]\n", fileName);
		duckdb_disconnect(&be->con);
		duckdb_close(&be->db);
		free(be);
		pq->backend = NULL;
		return;
	}

	char sql[4096];
	snprintf(sql, sizeof(sql), "COPY %s TO '%s' (FORMAT PARQUET)", pq->tableName, fileName);

	duckdb_result result;
	if (duckdb_query(be->con, sql, &result) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to write [%s]: %s\n", fileName, duckdb_result_error(&result));
	}
	else
	{
		fprintf(stderr, "parquet: wrote [%s]\n", fileName);
		s_totalFile++;
	}
	duckdb_destroy_result(&result);

	duckdb_disconnect(&be->con);
	duckdb_close(&be->db);
	free(be);
	pq->backend = NULL;
}

//------------------------------------------------------------------------------
// parquetFileNameBuild: output file name for the rotation window starting at
// windowStartNS. the window start time (UTC) is inserted before the file
// extension e.g. out.parq -> out_20230822_133000.parq. with rotation
// disabled the configured name is used as is
//------------------------------------------------------------------------------
static const char* parquetFileNameBuild(u64 windowStartNS)
{
	if (s_rotatePeriodNS == 0)
	{
		return s_outputName;
	}

	// file extension = everything from the last '.' in the last path component
	const char* ext = strrchr(s_outputName, '.');
	if ((ext == NULL) || (strchr(ext, '/') != NULL))
	{
		ext = s_outputName + strlen(s_outputName);
	}

	static char name[4096];
	clock_date_t c = ns2clock_utc(windowStartNS);
	snprintf(name, sizeof(name), "%.*s_%04d%02d%02d_%02d%02d%02d%s", (int)(ext - s_outputName), s_outputName, c.year, c.month, c.day, c.hour, c.min, c.sec, ext);
	return name;
}

//------------------------------------------------------------------------------
// parquetRotate: flush the current rotation window out to its parquet file
// and start a new window: fresh duckdb instance + protocol schema. only
// called once a protocol has been selected (tableName != NULL)
//------------------------------------------------------------------------------
static void parquetRotate(Parquet_t* pq)
{
	parquetClose(pq, parquetFileNameBuild(s_rotateBucket * s_rotatePeriodNS));

	if (!parquetOpen(pq))
	{
		exit(1);
	}
	if ((s_schemaCreate == NULL) || !s_schemaCreate(pq))
	{
		fprintf(stderr, "parquet: failed to recreate the protocol schema on rotation\n");
		exit(1);
	}
}

//------------------------------------------------------------------------------
// parquetRotateCheck: per packet rotation on pcap time period boundaries.
// rotation waits for a protocol to be selected (tableName set), until then
// only the window index is tracked
//------------------------------------------------------------------------------
void parquetRotateCheck(Parquet_t* pq, u64 ts)
{
	if (s_rotatePeriodNS == 0)
	{
		return;
	}

	u64 bucket = ts / s_rotatePeriodNS;
	if (!s_rotateBucketValid)
	{
		s_rotateBucket = bucket;
		s_rotateBucketValid = true;
	}
	else if (bucket != s_rotateBucket)
	{
		if (pq->tableName != NULL)
		{
			parquetRotate(pq);
		}
		s_rotateBucket = bucket;
	}
}

//------------------------------------------------------------------------------
// parquetFinalClose: flush the final rotation window. with rotation enabled
// but no packets seen there is no window start time, fall back to the plain
// output name
//------------------------------------------------------------------------------
void parquetFinalClose(Parquet_t* pq)
{
	if ((s_rotatePeriodNS > 0) && (s_rotateBucketValid))
	{
		parquetClose(pq, parquetFileNameBuild(s_rotateBucket * s_rotatePeriodNS));
	}
	else
	{
		parquetClose(pq, s_outputName);
	}
}

//------------------------------------------------------------------------------
// parquetFileTotal: number of parquet files written
//------------------------------------------------------------------------------
u64 parquetFileTotal(void)
{
	return s_totalFile;
}

//------------------------------------------------------------------------------
// parquetSchemaCreate: build the CREATE TABLE statement from the generic
// column table, create the protocol table and its appender
//------------------------------------------------------------------------------
bool parquetSchemaCreate(Parquet_t* pq, const char* tableName, const ParquetColumn_t* columns, u32 columnCount)
{
	// generic column type -> duckdb column type
	static const char* typeName[] =
	{
		"UTINYINT",			// PARQUET_TYPE_U8
		"USMALLINT",		// PARQUET_TYPE_U16
		"UINTEGER",			// PARQUET_TYPE_U32
		"UBIGINT",			// PARQUET_TYPE_U64
		"INTEGER",			// PARQUET_TYPE_S32
		"BIGINT",			// PARQUET_TYPE_S64
		"DOUBLE",			// PARQUET_TYPE_DOUBLE
		"VARCHAR",			// PARQUET_TYPE_STRING
		"DECIMAL(16,4)",	// PARQUET_TYPE_DECIMAL16_4
		"DECIMAL(20,8)",	// PARQUET_TYPE_DECIMAL20_8
	};

	static char sql[kKB(32)];
	u32 pos = snprintf(sql, sizeof(sql), "CREATE TABLE %s (", tableName);
	for (u32 i = 0; i < columnCount; i++)
	{
		// column names are quoted defensively (they are plain identifiers)
		pos += snprintf(sql + pos, sizeof(sql) - pos, "%s\"%s\" %s", (i > 0) ? ", " : "", columns[i].name, typeName[columns[i].type]);
		if (pos >= sizeof(sql) - 64)
		{
			fprintf(stderr, "parquet: schema for [%s] exceeds the sql buffer\n", tableName);
			return false;
		}
	}
	snprintf(sql + pos, sizeof(sql) - pos, ")");

	ParquetDuckDB_t* be = BACKEND(pq);

	duckdb_result result;
	if (duckdb_query(be->con, sql, &result) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to create schema for [%s]: %s\n", tableName, duckdb_result_error(&result));
		duckdb_destroy_result(&result);
		return false;
	}
	duckdb_destroy_result(&result);

	pq->tableName = tableName;

	if (duckdb_appender_create(be->con, NULL, tableName, &be->appender) == DuckDBError)
	{
		fprintf(stderr, "parquet: failed to create appender for [%s]\n", tableName);
		return false;
	}

	return true;
}

//------------------------------------------------------------------------------
// row append API: thin wrappers over the duckdb appender so the decoders
// never call duckdb directly (see parq.h)
//------------------------------------------------------------------------------
void parquetRowBegin(Parquet_t* pq)
{
	duckdb_appender_begin_row(BACKEND(pq)->appender);
}

bool parquetRowEnd(Parquet_t* pq)
{
	if (duckdb_appender_end_row(BACKEND(pq)->appender) == DuckDBError)
	{
		fprintf(stderr, "parquet: append failed: %s\n", duckdb_appender_error(BACKEND(pq)->appender));
		return false;
	}
	return true;
}

void parquetAppendU8(Parquet_t* pq, u8 v)
{
	duckdb_append_uint8(BACKEND(pq)->appender, v);
}

void parquetAppendU16(Parquet_t* pq, u16 v)
{
	duckdb_append_uint16(BACKEND(pq)->appender, v);
}

void parquetAppendU32(Parquet_t* pq, u32 v)
{
	duckdb_append_uint32(BACKEND(pq)->appender, v);
}

void parquetAppendU64(Parquet_t* pq, u64 v)
{
	duckdb_append_uint64(BACKEND(pq)->appender, v);
}

void parquetAppendS32(Parquet_t* pq, s32 v)
{
	duckdb_append_int32(BACKEND(pq)->appender, v);
}

void parquetAppendS64(Parquet_t* pq, s64 v)
{
	duckdb_append_int64(BACKEND(pq)->appender, v);
}

void parquetAppendDouble(Parquet_t* pq, double v)
{
	duckdb_append_double(BACKEND(pq)->appender, v);
}

void parquetAppendStr(Parquet_t* pq, const char* s)
{
	if ((s != NULL) && (s[0] != 0))
	{
		duckdb_append_varchar(BACKEND(pq)->appender, s);
	}
	else
	{
		duckdb_append_null(BACKEND(pq)->appender);
	}
}

void parquetAppendNull(Parquet_t* pq)
{
	duckdb_append_null(BACKEND(pq)->appender);
}
