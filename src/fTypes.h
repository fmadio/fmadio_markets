#pragma once

//------------------------------------------------------------------------------
//
// fTypes.h
//
// Project fixed-width types and helper macros.
//
//------------------------------------------------------------------------------

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

typedef __uint128_t	u128;

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int 		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;


#define kKB(a)		((u64)(a) << 10)
#define kMB(a)		((u64)(a) << 20)
#define kGB(a)		((u64)(a) << 30)

#define k1E9		1000000000ULL

#define INLINE		inline

// epoch in nanos in GMT timezone
static INLINE u64 clock_ns(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (u64)tv.tv_sec *(u64)1e9 +(u64)tv.tv_usec * (u64)1e3;
}

static INLINE u64 rdtsc(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}

static INLINE u32 swap32(const u32 a)
{
	return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

static INLINE u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

static INLINE u64 swap64(const u64 a)
{
	return swap32(a>>32ULL) | ( (u64)swap32(a) << 32ULL); 
}

static INLINE u128 swap128(const u128 a)
{
	u64* p = (u64*)&a;
	return (u128)swap64(p[1]) | ((u128)swap64(p[0]));
}


static INLINE char* FormatTS(u64 ts)
{
	u64 usec = ts / 1000ULL;
	u64 msec = usec / 1000ULL;
	u64 sec = msec / 1000ULL;
	u64 min = sec / 60ULL;
	u64 hour = min / 60ULL;

	u64 nsec = ts - usec*1000ULL;
	usec = usec - msec*1000ULL;
	msec = msec - sec*1000ULL;
	sec = sec - min*60ULL;
	min = min - hour*60ULL;

	static char List[16][128];
	static int Pos = 0;

	char* S = List[Pos];
	Pos = (Pos + 1) & 0xf;

	sprintf(S, "%02llu:%02llu:%02llu.%03llu.%03llu.%03llu", hour % 24, min, sec, msec,usec, nsec);
	return S;
}

// calendar date split of a nanosecond epoch timestamp
typedef struct
{
	s32		year;
	s32		month;
	s32		day;
	s32		hour;
	s32		min;
	s32		sec;

} clock_date_t;

// epoch nanos -> calendar date in the local timezone
static INLINE clock_date_t ns2clock(u64 TS)
{
	time_t t = TS / k1E9;
	struct tm tm;
	localtime_r(&t, &tm);

	clock_date_t c;
	c.year	= tm.tm_year + 1900;
	c.month	= tm.tm_mon + 1;
	c.day	= tm.tm_mday;
	c.hour	= tm.tm_hour;
	c.min	= tm.tm_min;
	c.sec	= tm.tm_sec;
	return c;
}

// epoch nanos -> calendar date in UTC
static INLINE clock_date_t ns2clock_utc(u64 TS)
{
	time_t t = TS / k1E9;
	struct tm tm;
	gmtime_r(&t, &tm);

	clock_date_t c;
	c.year	= tm.tm_year + 1900;
	c.month	= tm.tm_mon + 1;
	c.day	= tm.tm_mday;
	c.hour	= tm.tm_hour;
	c.min	= tm.tm_min;
	c.sec	= tm.tm_sec;
	return c;
}

static inline void  ns2str(u8* Str, u64 TS)
{
	clock_date_t c = ns2clock(TS);

	u64 sec = TS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf((char*)Str, "%04i%02i%02i_%02i%02i%02i.%03i.%03i.%03i", c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec);
}
static inline void  ns2str_pretty(u8* Str, u64 TS) 
{
	clock_date_t c = ns2clock(TS);

	u64 sec = TS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf((char*)Str, "%04i-%02i-%02i %02i:%02i:%02i.%03i.%03i.%03i", c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec);
}
static inline void  ns2str_pretty_utc(u8* Str, u64 TS) 
{
	clock_date_t c = ns2clock_utc(TS);

	u64 sec = TS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf((char*)Str, "%04i-%02i-%02i %02i:%02i:%02i.%03i.%03i.%03i UTC", c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec);
}

