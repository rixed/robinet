top_srcdir = ./
PKG_NAME = robinet
SOURCES  = \
	tools.ml clock.ml log.ml \
	persist.ml peg.ml \
	fifo.ml metric.ml \
	dns.ml url.ml http.ml \
	tcp.ml udp.ml \
	ip.ml icmp.ml arp.ml \
	vlan.ml eth.ml dhcp.ml \
	sll.ml \
	pcap.ml packet.ml \
	host.ml localhost.ml \
	html.ml browser.ml \
	hub.ml net.ml \
	opache.ml myadmin.ml
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
	examples/test_ping.byte
EXAMPLES_OPT = $(EXAMPLES_BYTE:.byte=.opt)
EXAMPLES = $(EXAMPLES_BYTE) $(EXAMPLES_OPT)

REQUIRES = bitstring bitstring.syntax batteries batteries.pa_string.syntax lwt lwt.unix lwt.extra lwt.syntax
SYNTAX=-syntax camlp4o

include $(top_srcdir)make.common

.PHONY: check examples

all: robinet.top examples

$(EXAMPLES): $(ARCHIVE)
$(EXAMPLES_OPT): $(XARCHIVE)

$(CLIB): $(C_SOURCES:.c=.o)
	$(AR) rcs $@ $^

check.byte: $(ARCHIVE)
check.opt: $(XARCHIVE)
check: check.byte check.opt
	@./check.byte && ./check.opt && echo "OK"


examples: $(EXAMPLES)

robinet.top: $(ARCHIVE)
	$(OCAMLMKTOP) -o $@ -package "findlib,$(REQUIRES)" -linkpkg $(ARCHIVE)

clean-spec:
	rm -f *.pcap
	rm -f examples/*.cm[ioxa] examples/*.o $(EXAMPLES)

