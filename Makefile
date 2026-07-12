CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu99 -I/usr/local/include -Isrc -Iprotocol/nasdaq_md_itch5 -Iprotocol/opra_md_pillar6
LDFLAGS = -L/usr/local/lib -lduckdb

SRCS    = src/main.c protocol/nasdaq_md_itch5/nasdaq_md_itch5.c protocol/opra_md_pillar6/opra_md_pillar6.c
HDRS    = src/fTypes.h src/fParquet.h protocol/nasdaq_md_itch5/nasdaq_md_itch5.h protocol/opra_md_pillar6/opra_md_pillar6.h

all: src/fmadio_markets

src/fmadio_markets: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o src/fmadio_markets $(SRCS) $(LDFLAGS)

clean:
	rm -f src/fmadio_markets
