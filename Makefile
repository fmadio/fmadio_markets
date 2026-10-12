CC      = gcc

CFLAGS  =
CFLAGS += -O2 -Wall -Wextra -std=gnu99
CFLAGS += -I/usr/local/include
CFLAGS += -Isrc

LDFLAGS  =
LDFLAGS += -L/usr/local/lib

SRCS  =
SRCS += src/main.c
SRCS += src/fProtocol.c
SRCS += src/tcpstream.c

# duckdb backend
LDFLAGS += -lduckdb
SRCS += src/parq_duckdb.c

HDRS  =
HDRS += src/fTypes.h
HDRS += src/fNetwork.h
HDRS += src/fParquet.h
HDRS += src/fCapture.h
HDRS += src/fProtocol.h
HDRS += src/parq.h
HDRS += src/tcpstream.h

# protocol decoders are auto discovered, NOT listed: every protocol/*/*.c is
# compiled in and self registers at program start (fProtocol.h), so protocol
# directories - including confidential ones that cannot appear in shared
# source - are added or removed without touching main.c or this Makefile
SRCS += $(sort $(wildcard protocol/*/*.c))
HDRS += $(sort $(wildcard protocol/*/*.h))

all: src/fmadio_markets

src/fmadio_markets: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o src/fmadio_markets $(SRCS) $(LDFLAGS)

# validation suites are auto discovered like the decoders: every protocol
# directory with a validate/Makefile provides a 'synthetic' target. runs
# each suite in order and stops on the first failure (nonzero exit, CI ready)
TESTS  =
TESTS += $(sort $(dir $(wildcard protocol/*/validate/Makefile)))

test: src/fmadio_markets
	@for t in $(TESTS); do \
		echo "==== $$t ===="; \
		$(MAKE) -C $$t synthetic || exit 1; \
	done

clean:
	rm -f src/fmadio_markets
