#------------------------------------------------------------------------------
# ITCH 5.0 decoder validation
#
#   make / make test   - synthetic validation: generate a pcap with all 23
#                        message types and check every field of the decoder
#                        parquet output
#   make real          - validate a production parquet against the 3rd party
#                        mdgap.csv reference (seq + timestamp comparison,
#                        End of Session artifact analysis). Override inputs:
#                        make real REAL_PARQUET=<file> REAL_CSV=<file>
#   make clean         - remove generated test files
#------------------------------------------------------------------------------

LUAJIT  = luajit
ROOT    = ../../..
DECODER = $(ROOT)/src/fmadio_markets

PCAP    = itch5_test.pcap
PARQUET = itch5_test.parquet

REAL_PARQUET = $(ROOT)/fmadio_markets.parquet
REAL_CSV     = $(ROOT)/mdgap.csv

.PHONY: all test real decoder clean

all: test

test: decoder $(PCAP)
	$(LUAJIT) validate.lua $(DECODER) $(PCAP) $(PARQUET)

real:
	$(LUAJIT) validate_real.lua $(REAL_PARQUET) $(REAL_CSV)

$(PCAP): gen_pcap.lua
	$(LUAJIT) gen_pcap.lua $(PCAP)

decoder:
	$(MAKE) -C $(ROOT)

clean:
	rm -f $(PCAP) $(PARQUET)
