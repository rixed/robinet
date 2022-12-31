// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2012, Cedric Cellier
 *
 * This file is part of RobiNet.
 *
 * RobiNet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RobiNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with RobiNet.  If not, see <http://www.gnu.org/licenses/>.
 */
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
    /* In recent kernels packets are buffered before being sent to userland in
     * batches. We don;'t want this to delay sniffing by more than 0.01s: */
    if (0 != pcap_set_timeout(handle, 10)) goto err;
    //if (0 != pcap_set_immediate_mode(handle, 1)) goto err;
    if (0 != pcap_setnonblock(handle, 1, errbuf)) goto err1;
    if (0 != pcap_activate(handle)) goto err;
    if (0 != set_filter(handle, filter)) goto err;

    return handle;
err:
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle));
err1:
    pcap_close(handle);
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

    size_t size = caml_string_length(str_); // believed to be faster than strlen()
    char const *str = String_val(str_);

    if (PCAP_ERROR == pcap_inject(handle, str, size)) {
        char *err_msg = pcap_geterr(handle);
        caml_failwith(err_msg);
    }

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_pcap_read(value wait_, value handle_)
{
    CAMLparam2(wait_, handle_);
    pcap_t *const handle = Pcap_val(handle_);
    bool const wait =
        // True by default:
        !Is_block(wait_) /* Aka None */ || Bool_val(Field(wait_, 0));

    struct pcap_pkthdr *hdr;
    u_char const *bytes;
    caml_release_runtime_system();
retry:
    switch (pcap_next_ex(handle, &hdr, &bytes)) {
        case 1: // Ok
            caml_acquire_runtime_system();
            break;
        case 0: // Timeout
            /* Retry automatically in case of timeout, to avoid acquiring
             * and releasing the giant lock. */
            if (wait) goto retry;
            caml_acquire_runtime_system();
            caml_raise_not_found();
            break;
        case -1:    // Error
            caml_acquire_runtime_system();
            caml_failwith(pcap_geterr(handle));
            break;
        case -2:    // End of savefile (should not happen)
            caml_acquire_runtime_system();
            caml_failwith("Hit end of savefile on device?");
            break;
    }

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
