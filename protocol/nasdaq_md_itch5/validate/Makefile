#------------------------------------------------------------------------------
# ITCH 5.0 decoder validation
#
#   make / make test   - synthetic validation: generate a pcap with all 23
#                        message types and check every field of the decoder
#                        parquet output (validate_synthetic.lua)
#   make real          - real data validation (validate_real.lua): decode the
#                        production pcap (zstd, streamed via zstdcat into the
#                        decoder stdin, temp parquet written into this
#                        directory) then check every message's pcap timestamp
#                        + mold seq number against the 3rd party mdgap
#                        reference csv. Override inputs:
#                        make real REAL_PCAP=<pcap[.zst]> REAL_CSV=<csv[.zst]>
#   make clean         - remove generated test files
#------------------------------------------------------------------------------

LUAJIT  = luajit
ROOT    = ../../..
DECODER = $(ROOT)/src/fmadio_markets

PCAP    = itch5_test.pcap
PARQUET = itch5_test.parquet

REAL_DIR     = $(ROOT)/data/protocol/nasdaq_md_itch5
REAL_PCAP    = $(REAL_DIR)/ny4-xnas-tvitch-20230822.pcap.zst
REAL_CSV     = $(REAL_DIR)/ny4-xnas-tvitch-20230822.pcap.mdgap.seqno.csv.zst
REAL_JSON_1M = $(REAL_DIR)/ny4-xnas-tvitch-20230822.pcap.tshark.json.1m.zst
REAL_PARQUET = ny4-xnas-tvitch-20230822.parquet

.PHONY: all test real json_1m decoder clean

all:

synthetic: decoder $(PCAP)
	$(LUAJIT) validate_synthetic.lua $(DECODER) $(PCAP) $(PARQUET)

real: decoder
	$(LUAJIT) validate_real.lua $(DECODER) $(REAL_PCAP) $(REAL_CSV) $(REAL_PARQUET)

# field level verification vs the OMI tshark ek json 1M packet slice.
# reuses the parquet from 'make real' when present, decodes otherwise
json_1m: decoder
	$(LUAJIT) validate_real_json_1m.lua $(REAL_PARQUET) $(REAL_JSON_1M) $(DECODER) $(REAL_PCAP)

$(PCAP): gen_pcap.lua
	$(LUAJIT) gen_pcap.lua $(PCAP)

decoder:
	$(MAKE) -C $(ROOT)

clean:
	rm -f $(PCAP) $(PARQUET) $(REAL_PARQUET)
