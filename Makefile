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
# The three libraries the interface is built on, vendored into www/ rather
# than fetched from a CDN at run time: a robinet program must remain a single
# binary that works on a machine with no network. They are committed alongside
# the sources; the `vendor' target below is what puts them there.
PICO_VERSION   = 2.1.1
ALPINE_VERSION = 3.16.3
UPLOT_VERSION  = 1.6.32

VENDORED_ASSETS = www/pico.min.css www/alpine.min.js \
                  www/uplot.min.js www/uplot.min.css

# The coastlines the map draws behind the network, from Natural Earth's
# 1:110m coastline (public domain), coarsened further by coastline.py. Like
# the libraries above it is committed rather than built: see the `coastline'
# target below.
COASTLINE = www/coast.js

# The page and its own script and style, then the coast and those libraries.
UI_ASSETS = www/index.html www/app.js www/style.css $(COASTLINE) \
            $(VENDORED_ASSETS)

# Tests that do not fit qtest's inline style: concurrency and the admin API.
# Run them on their own for a longer, harder run:
#   tests/stress.opt <seconds> <threads>
EXTRA_TESTS = tests/stress.opt


include $(top_srcdir)make.common

.PHONY: examples run vendor coastline

all: robinet.top examples $(EXTRA_TESTS)

run: robinet.top
	rlwrap ./robinet.top -init robinet.init

$(EXAMPLES_BYTE): $(ARCHIVE)
$(EXAMPLES_OPT): $(XARCHIVE)
$(EXTRA_TESTS): $(XARCHIVE)

# .depend is computed by scanning the sources, and this one is generated: were
# it missing from that scan, nothing would know that myadmin_ui.ml uses it, and
# a change to www/ would leave the two disagreeing about it.
.depend: myadmin_assets.ml

# Fetch the vendored libraries, at the versions pinned above.
#
# Deliberately not a prerequisite of anything: a build must never reach the
# network on its own, and these files are committed. Run it by hand to fetch
# them for the first time, or after changing one of the versions above -- then
# read `git diff' before committing, which is the only check on what a CDN just
# handed us that is worth anything.
CDN = https://cdn.jsdelivr.net/npm

# Fetch $(2) into $(1), leaving whatever is there alone unless the transfer
# succeeded whole: a truncated library would be embedded into the binary and
# fail in the browser, a long way from here.
define fetch
	@curl --fail --silent --show-error --location --output "$(1).part" "$(2)" || \
	   { rm -f "$(1).part" ; exit 1 ; }
	@mv "$(1).part" "$(1)"
endef

vendor:
	@echo 'Fetching Pico $(PICO_VERSION), Alpine $(ALPINE_VERSION) and uPlot $(UPLOT_VERSION) into www/'
	$(call fetch,www/pico.min.css,$(CDN)/@picocss/pico@$(PICO_VERSION)/css/pico.min.css)
	$(call fetch,www/alpine.min.js,$(CDN)/alpinejs@$(ALPINE_VERSION)/dist/cdn.min.js)
	@# The [iife] build, which defines a global: the page loads it with a
	@# plain <script>, not as a module. Named here as the others are.
	$(call fetch,www/uplot.min.js,$(CDN)/uplot@$(UPLOT_VERSION)/dist/uPlot.iife.min.js)
	$(call fetch,www/uplot.min.css,$(CDN)/uplot@$(UPLOT_VERSION)/dist/uPlot.min.css)
	@# Assets are embedded below as {robinet|...|robinet} quoted strings, so
	@# a file containing that delimiter would break the generated source in a
	@# way that says nothing about where it came from. Say it here instead.
	@for f in $(VENDORED_ASSETS) ; do \
	   if grep -q 'robinet' "$$f" ; then \
	     echo "$$f contains \"robinet\", which delimits the embedded assets: myadmin_assets.ml cannot hold it as it stands" >&2 ; \
	     exit 1 ; \
	   fi ; \
	 done
	@ls -l $(VENDORED_ASSETS)

# Rebuild the coastlines. Like `vendor', by hand and not from the build: the
# result is committed, and the shoreline of the world is not a moving target.
NE_CDN = https://naciscdn.org/naturalearth

coastline:
	@echo 'Building $(COASTLINE) from the Natural Earth 1:110m coastline'
	$(call fetch,ne_110m_coastline.zip,$(NE_CDN)/110m/physical/ne_110m_coastline.zip)
	@python3 coastline.py ne_110m_coastline.zip $(COASTLINE)
	@$(RM) ne_110m_coastline.zip
	@ls -l $(COASTLINE)

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
