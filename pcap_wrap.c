#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/custom.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#if CAML_VERSION > 31200 
#   include <caml/threads.h> 
#else 
#   include <caml/signals.h> 
#   define caml_release_runtime_system caml_enter_blocking_section 
#   define caml_acquire_runtime_system caml_leave_blocking_section 
#endif 

/*
 * Custom ops on pcap handles
 */

#define Pcap_val(v) (*((pcap_t **)Data_custom_val(v)))

static void finalize(value v)
{
	pcap_t *const handle = Pcap_val(v);
	pcap_close(handle);
}

static struct custom_operations ops = {
	.identifier = "org.happyleptic.pcap.1",
	.finalize = finalize,
	.compare = custom_compare_default,
	.hash = custom_hash_default,
	.serialize = custom_serialize_default,
	.deserialize = custom_deserialize_default,
};

/*
 * Wrappers around the few libpcap functions we need
 */

static int set_filter(pcap_t *handle, char const *filter)
{
    struct bpf_program fp;
    if (! filter || filter[0] == '\0') return 0;
    if (0 != pcap_compile(handle, &fp, filter, 1, 0)) return -1;
    if (0 != pcap_setfilter(handle, &fp)) return -1;

	return 0;
}


static pcap_t *make_pcap(char const *ifname, bool promisc, char const *filter, size_t snaplen, char *errbuf)
{
    if (! snaplen) snaplen = 65535; // FIXME: let libpcap deal with it

    pcap_t *handle = pcap_create(ifname, errbuf);
    if (! handle) caml_failwith(errbuf);

    if (0 != pcap_set_promisc(handle, promisc)) goto err;
	if (0 != pcap_set_snaplen(handle, snaplen)) goto err;
    if (0 != pcap_activate(handle)) goto err;
    if (0 != set_filter(handle, filter)) goto err;

    return handle;
err:
    pcap_close(handle);
	snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle));
	return NULL;
}


CAMLprim value wrap_pcap_make(value ifname_, value promisc_, value filter_, value snaplen_)
{
	CAMLparam4(ifname_, promisc_, filter_, snaplen_);
    char errbuf[PCAP_ERRBUF_SIZE] = "";

	char const *const ifname = String_val(ifname_);
	bool const promisc = Bool_val(promisc_);
	char const *const filter = String_val(filter_);
	unsigned const snaplen = Unsigned_int_val(snaplen_);

	pcap_t *handle = make_pcap(ifname, promisc, filter, snaplen, errbuf);
	if (! handle) caml_failwith(errbuf);

	CAMLlocal1(v);
	v = caml_alloc_custom(&ops, sizeof(handle), 1000 /* the size behind a handle */, 100000);
	memcpy(Data_custom_val(v), &handle, sizeof(handle));
	CAMLreturn(v);
}

CAMLprim value wrap_pcap_inject(value handle_, value str_)
{
	CAMLparam2(handle_, str_);

	pcap_t *const handle = Pcap_val(handle_);

	size_t size = caml_string_length(str_);	// believed to be faster than strlen()
	char const *str = String_val(str_);

	if (-1 == pcap_inject(handle, str, size)) {
		caml_failwith("Cannot inject packet");
	}

	CAMLreturn(Val_unit);
}

CAMLprim value wrap_pcap_read(value handle_)
{
	CAMLparam1(handle_);
	pcap_t *const handle = Pcap_val(handle_);

	struct pcap_pkthdr *hdr;
	u_char const *bytes;
	caml_release_runtime_system();
retry:
	switch (pcap_next_ex(handle, &hdr, &bytes)) {
		case 1: // Ok
			break;
		case 0:	// timeout
			goto retry;
		case -1:	// Error
			caml_acquire_runtime_system();
			caml_failwith(pcap_geterr(handle));
			break;
		case -2:	// End of savefile (should not happen)
			caml_acquire_runtime_system();
			caml_failwith("Hit end of savefile on device?");
			break;
	}
	caml_acquire_runtime_system();

	CAMLlocal3(result, ts, pkt);
	pkt = caml_alloc_string(hdr->caplen);
	memcpy(String_val(pkt), bytes, hdr->caplen);
	Byte(pkt, hdr->caplen+1) = 0;

	ts = caml_copy_double(hdr->ts.tv_sec + (double)hdr->ts.tv_usec * 0.000001);

	result = caml_alloc_tuple(2);
	Field(result, 0) = ts;
	Field(result, 1) = pkt;

	CAMLreturn(result);
}
