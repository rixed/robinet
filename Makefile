top_srcdir = ./
PKG_NAME = robinet

SOURCES  = \
	distribution.ml \
	private.ml \
	condvar.ml \
	clock.ml \
	metric.ml \
	log.ml \
	widget.ml \
	simulation.ml \
	tools.ml \
	ordArray.ml \
	payload.ml \
	persist.ml \
	peg.ml \
	pcap.ml \
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
	tap.ml \
	packet.ml \
	sockopt.ml \
	hub.ml \
	host.ml \
	named.ml \
	localhost.ml \
	html.ml \
	browser.ml \
	net.ml \
	dhcpd.ml \
	ip_nat.ml \
	router.ml \
	opache.ml \
	search.ml \
	myadmin_common.ml \
	myadmin_home.ml \
	myadmin_logs.ml \
	myadmin_api.ml \
	myadmin_assets.ml \
	myadmin_ui.ml \
	myadmin.ml \
	sim.ml \
	wrapper.ml

C_SOURCES = \
	pcap_wrap.c \
	eth_vendors.c \
	tap_wrap.c \
	iface_wrap.c \
	sockopt_wrap.c \
	condvar_wrap.c

CLIB_SHORT = robinetext
CLIB = lib$(CLIB_SHORT).a
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
	examples/simu_dc_mirroring.byte \
	examples/admin_demo.byte

EXAMPLES_OPT = $(EXAMPLES_BYTE:.byte=.opt)
EXAMPLES = $(EXAMPLES_BYTE) $(EXAMPLES_OPT)

REQUIRES = bitstring ppx_bitstring batteries yojson ppx_deriving_yojson

# The administration interface is written as ordinary files in www/ and
# compiled into the library, so that a robinet program has nothing to install
# beside it and no directory to locate at run time.
UI_ASSETS = www/index.html www/app.js www/style.css

# Tests that do not fit qtest's inline style: concurrency and the admin API.
# Run them on their own for a longer, harder run:
#   tests/stress.opt <seconds> <threads>
EXTRA_TESTS = tests/stress.opt


include $(top_srcdir)make.common

.PHONY: examples run

all: robinet.top examples $(EXTRA_TESTS)

run: robinet.top
	rlwrap ./robinet.top -init robinet.init

$(EXAMPLES_BYTE): $(ARCHIVE)
$(EXAMPLES_OPT): $(XARCHIVE)
$(EXTRA_TESTS): $(XARCHIVE)

myadmin_assets.ml: $(UI_ASSETS)
	@echo 'Embedding $(UI_ASSETS) into $@'
	@{ echo '(* Generated from www/ by the Makefile. Do not edit. *)' ;\
	   echo 'let all = [' ;\
	   for f in $(UI_ASSETS) ; do \
	     echo "  \"$$(basename $$f)\", {robinet|" ;\
	     cat "$$f" ;\
	     echo '|robinet} ;' ;\
	   done ;\
	   echo ']' ;\
	 } > $@

$(CLIB): $(C_SOURCES:.c=.o)
	$(AR) rcs $@ $^

examples: $(EXAMPLES)
	@if which setcap > /dev/null 2>&1 ; then \
	   echo "You should run:" ;\
	   for f in $(EXAMPLES); do \
	     echo "sudo setcap cap_net_raw,cap_net_admin=eip $$f" ;\
	   done ;\
	 fi

robinet.top: $(ARCHIVE)
	$(OCAMLMKTOP) $(WARNS) -o $@ -package "findlib $(REQUIRES)" $(ARCHIVE)
	@if which setcap > /dev/null 2>&1 ; then \
	   echo "You should run:" ;\
	   echo "sudo setcap cap_net_raw,cap_net_admin=eip $@" ;\
	 fi

clean-spec:
	$(RM) examples/*.cm[ioxa] examples/*.o $(EXAMPLES)
	$(RM) tests/*.cm[ioxa] tests/*.o tests/*.annot $(EXTRA_TESTS)
	$(RM) myadmin_assets.ml
