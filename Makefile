top_srcdir = ./
PKG_NAME = robinet
SOURCES  = \
	tools.ml \
	clock.ml \
	log.ml \
	persist.ml \
	peg.ml \
	metric.ml \
	dns.ml \
	url.ml \
	http.ml \
	tcp.ml \
	udp.ml \
	ip.ml \
	ip6.ml \
	icmp.ml \
	icmp6.ml \
	arp.ml \
	vlan.ml \
	eth.ml \
	dhcp.ml \
	sll.ml \
	pcap.ml \
	packet.ml \
	hub.ml \
	host.ml \
	localhost.ml \
	html.ml \
	browser.ml \
	net.ml \
	dhcpd.ml \
	router.ml \
	opache.ml \
	myadmin.ml \
	sim.ml \

C_SOURCES = pcap_wrap.c eth_vendors.c
CLIB = libpcapw.a
LIBS = -cclib -lpcap
EXAMPLES_BYTE = \
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
	examples/simu_perfweb.byte

EXAMPLES_OPT = $(EXAMPLES_BYTE:.byte=.opt)
EXAMPLES = $(EXAMPLES_BYTE) $(EXAMPLES_OPT)

REQUIRES = bitstring bitstring.syntax batteries
SYNTAX=-syntax camlp4o

include $(top_srcdir)make.common

.PHONY: examples run

all: robinet.top examples

run: robinet.top
	rlwrap ./robinet.top -init robinet.init

$(EXAMPLES): $(ARCHIVE)
$(EXAMPLES_OPT): $(XARCHIVE)

$(CLIB): $(C_SOURCES:.c=.o)
	$(AR) rcs $@ $^

examples: $(EXAMPLES)
	@for f in $(EXAMPLES); do \
		sudo setcap cap_net_raw,cap_net_admin=eip $$f ;\
	 done

robinet.top: $(ARCHIVE)
	$(OCAMLMKTOP) -o $@ -package "findlib,$(REQUIRES)" -linkpkg $(ARCHIVE)
	sudo setcap cap_net_raw,cap_net_admin=eip $@

clean-spec:
	rm -f examples/*.cm[ioxa] examples/*.o $(EXAMPLES)

