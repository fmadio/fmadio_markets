#------------------------------------------------------------------------------
# FIX 4.2 decoder validation
#
#   make synthetic     - synthetic validation: generate a TCP pcap with a
#                        full FIX session (both directions, split / packed /
#                        out of order segments, LENGTH/DATA, repeating group,
#                        bad checksum, mid stream start, non FIX flow) and
#                        check the decoder parquet output field values
#                        (validate_synthetic.lua)
#   make real          - PENDING: no FIX capture under data/protocol/fix42/
#   make clean         - remove generated test files
#------------------------------------------------------------------------------

LUAJIT  = luajit
ROOT    = ../../..
DECODER = $(ROOT)/src/fmadio_markets

PCAP    = fix42_test.pcap
PARQUET = fix42_test.parq

.PHONY: all synthetic decoder clean

all:

synthetic: decoder $(PCAP)
	$(LUAJIT) validate_synthetic.lua $(DECODER) $(PCAP) $(PARQUET)

$(PCAP): gen_pcap.lua
	$(LUAJIT) gen_pcap.lua $(PCAP)

decoder:
	$(MAKE) -C $(ROOT)

clean:
	rm -f $(PCAP) $(PARQUET) $(PARQUET).auto
