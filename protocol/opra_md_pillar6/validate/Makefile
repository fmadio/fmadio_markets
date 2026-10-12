#------------------------------------------------------------------------------
# OPRA Pillar Binary v6 decoder validation
#
#   make synthetic     - synthetic validation: generate a pcap with every
#                        message category (a d f k q C H R Y), all BBO
#                        appendage variants, multiple denominator codes,
#                        production/retransmission/playback and GTH endpoints
#                        plus negative cases, then check every field of the
#                        decoder parquet output (validate_synthetic.lua)
#   make omi           - real capture cross validation: slice OMI_PACKETS
#                        packets off a real OPRA capture (REAL_PCAP), decode
#                        with both the fmadio decoder and tshark + the OMI
#                        wireshark lua dissector, compare every shared field
#                        per message (validate_omi.lua). Override inputs:
#                        make omi REAL_PCAP=... OMI_PACKETS=...
#   make clean         - remove generated test files
#
# Seq gap validation (mirroring nasdaq_md_itch5/validate make real) is pending
# a third party seq number reference under data/protocol/opra_md_pillar6/;
# see opra_md_pillar6.md section 9.
#------------------------------------------------------------------------------

LUAJIT  = luajit
ROOT    = ../../..
DECODER = $(ROOT)/src/fmadio_markets

PCAP    = opra6_test.pcap
PARQUET = opra6_test.parq

OMI_DISSECTOR = $(ROOT)/omi-wireshark-lua/Siac/Opra/Output/Siac_Opra_Output_Obi_v6_3_a_Dissector.lua
REAL_PCAP    ?= /mnt/git/databento-pcaps/opra/2023-08-22-1-hour/ny4-opra-new-a-20230822T140000.pcap
OMI_PACKETS  ?= 100000
OMI_PCAP      = omi_slice.pcap
OMI_PARQUET   = omi_slice.parq

.PHONY: all synthetic omi decoder clean

all: synthetic

synthetic: decoder $(PCAP)
	$(LUAJIT) validate_synthetic.lua $(DECODER) $(PCAP) $(PARQUET)

$(PCAP): gen_pcap.lua
	$(LUAJIT) gen_pcap.lua $(PCAP)

omi: decoder $(OMI_PCAP)
	$(LUAJIT) validate_omi.lua $(DECODER) $(OMI_PCAP) $(OMI_DISSECTOR) $(OMI_PARQUET)

$(OMI_PCAP):
	editcap -F pcap -r $(REAL_PCAP) $@ 1-$(OMI_PACKETS)

decoder:
	$(MAKE) -C $(ROOT)

clean:
	rm -f $(PCAP) $(PARQUET) $(OMI_PCAP) $(OMI_PARQUET)
