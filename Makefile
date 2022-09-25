top_srcdir = ./
PKG_NAME = robinet
SOURCES  = \
	distribution.ml \
	private.ml \
	clock.ml \
	log.ml \
	tools.ml \
	persist.ml \
	peg.ml \
	metric.ml \
	url.ml \
	http.ml \
	tcp.ml \
	udp.ml \
	ip.ml \
	ip6.ml \
	icmp.ml \
	icmp6.ml \
	dns.ml \
	arp.ml \
	vlan.ml \
	eth.ml \
	dhcp.ml \
	sll.ml \
	pcap.ml \
	tap.ml \
	packet.ml \
	hub.ml \
	host.ml \
	named.ml \
	localhost.ml \
	html.ml \
	browser.ml \
	net.ml \
	dhcpd.ml \
	router.ml \
	opache.ml \
	myadmin.ml \
	sim.ml \

C_SOURCES = pcap_wrap.c eth_vendors.c tap_wrap.c
CLIB = librobinetext.a
# libpcap elsewhere? Call make with:
# LIBS="-cclib -L/usr/local/lib -cclib -lpcap"
LIBS += -cclib -lpcap
EXAMPLES_BYTE = \
	examples/router_frenzy.byte \
	examples/arp_query.byte \
	examples/tcp_test.byte \
	examples/dns_query.byte \
	examples/http_load.byte \
	examples/sock_test.byte \
	examples/tunnel.byte \
	examples/beautify_html.byte \
	examples/http_echo_server.byte \
	examples/wanaplay.byte \
	examples/test_dhcp.byte \
	examples/http_static_server.byte \
	examples/beautify_mac.byte \
	examples/test_ping.byte \
	examples/capecho.byte \
	examples/load_tester.byte \
	examples/pcap_reorder.byte \
	examples/simu_perfweb.byte \
	examples/simu_dc_mirroring.byte

EXAMPLES_OPT = $(EXAMPLES_BYTE:.byte=.opt)
EXAMPLES = $(EXAMPLES_BYTE) $(EXAMPLES_OPT)

REQUIRES = bitstring ppx_bitstring batteries

include $(top_srcdir)make.common

.PHONY: examples run

all: robinet.top examples

run: robinet.top
	rlwrap ./robinet.top -init robinet.init

$(EXAMPLES_BYTE): $(ARCHIVE)
$(EXAMPLES_OPT): $(XARCHIVE)

$(CLIB): $(C_SOURCES:.c=.o)
	$(AR) rcs $@ $^

examples: $(EXAMPLES)
	@if which setcap > /dev/null 2>&1 ; then \
	   for f in $(EXAMPLES); do \
	     sudo setcap cap_net_raw,cap_net_admin=eip $$f ;\
	   done ;\
	 fi

robinet.top: $(ARCHIVE)
	$(OCAMLMKTOP) $(WARNS) -o $@ -package "findlib $(REQUIRES)" $(ARCHIVE)
	@if which setcap > /dev/null 2>&1 ; then \
	   sudo setcap cap_net_raw,cap_net_admin=eip $@ ;\
	 fi

clean-spec:
	rm -f examples/*.cm[ioxa] examples/*.o $(EXAMPLES)
