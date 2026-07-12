#------------------------------------------------------------------------------
# OPRA Pillar Binary v6 decoder validation
#
#   make synthetic     - synthetic validation: generate a pcap with every
#                        message category (a d f k q C H R Y), all BBO
#                        appendage variants, multiple denominator codes,
#                        production/retransmission/playback and GTH endpoints
#                        plus negative cases, then check every field of the
#                        decoder parquet output (validate_synthetic.lua)
#   make clean         - remove generated test files
#
# Real capture validation (mirroring nasdaq_md_itch5/validate make real /
# json_1m) is pending an OPRA capture + third party reference under
# data/protocol/opra_md_pillar6/; see opra_md_pillar6.md section 9.
#------------------------------------------------------------------------------

LUAJIT  = luajit
ROOT    = ../../..
DECODER = $(ROOT)/src/fmadio_markets

PCAP    = opra6_test.pcap
PARQUET = opra6_test.parq

.PHONY: all synthetic decoder clean

all: synthetic

synthetic: decoder $(PCAP)
	$(LUAJIT) validate_synthetic.lua $(DECODER) $(PCAP) $(PARQUET)

$(PCAP): gen_pcap.lua
	$(LUAJIT) gen_pcap.lua $(PCAP)

decoder:
	$(MAKE) -C $(ROOT)

clean:
	rm -f $(PCAP) $(PARQUET)
