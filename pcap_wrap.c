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
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#ifdef __linux__
#   include <linux/sockios.h>
#endif
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
    if (handle) pcap_close(handle);
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

// The OCaml [Pcap.direction], in the order of its constructors:
static pcap_direction_t const directions[] = { PCAP_D_INOUT, PCAP_D_IN, PCAP_D_OUT };

static pcap_t *make_pcap(char const *ifname, bool promisc, char const *filter, size_t snaplen, pcap_direction_t direction, bool blocking, char *errbuf)
{
    if (! snaplen) snaplen = 65535; // FIXME: let libpcap deal with it

    pcap_t *handle = pcap_create(ifname, errbuf);
    if (! handle) caml_failwith(errbuf);

    if (0 != pcap_set_promisc(handle, promisc)) goto err;
    if (0 != pcap_set_snaplen(handle, snaplen)) goto err;
    // Ask libpcap to ask the kernel not to buffer packets:
    if (0 != pcap_set_immediate_mode(handle, 1)) goto err;
    // Also, unless blocking, not to wait when there are no packets at all,
    // nor for room to send:
    if (0 != pcap_setnonblock(handle, ! blocking, errbuf)) goto err1;
    // Nanosecond timestamps where the platform has them (else microseconds):
    (void)pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
    // We will implement timeout ourselves
    if (0 != pcap_activate(handle)) goto err;
    if (0 != set_filter(handle, filter)) goto err;
    if (direction != PCAP_D_INOUT && 0 != pcap_setdirection(handle, direction)) goto err;

    return handle;
err:
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle));
err1:
    pcap_close(handle);
    return NULL;
}

CAMLprim value wrap_pcap_make(value ifname_, value promisc_, value filter_, value snaplen_, value direction_, value blocking_)
{
    CAMLparam5(ifname_, promisc_, filter_, snaplen_, direction_);
    CAMLxparam1(blocking_);
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    char const *const ifname = String_val(ifname_);
    bool const promisc = Bool_val(promisc_);
    char const *const filter = String_val(filter_);
    unsigned const snaplen = Unsigned_int_val(snaplen_);
    pcap_direction_t const direction = directions[Int_val(direction_)];
    bool const blocking = Bool_val(blocking_);

    pcap_t *handle = make_pcap(ifname, promisc, filter, snaplen, direction, blocking, errbuf);
    if (! handle) caml_failwith(errbuf);

    CAMLlocal1(v);
    v = caml_alloc_custom(&ops, sizeof(handle), 1000 /* the size behind a handle */, 100000);
    memcpy(Data_custom_val(v), &handle, sizeof(handle));
    CAMLreturn(v);
}

CAMLprim value wrap_pcap_make_byte(value *argv, int argn)
{
    (void)argn;
    return wrap_pcap_make(argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
}

CAMLprim value wrap_pcap_close(value handle_)
{
    CAMLparam1(handle_);
    pcap_t *handle = Pcap_val(handle_);
    if (! handle) caml_failwith("Pcap handle has been closed");
    pcap_close(handle);
    handle = NULL;
    memcpy(Data_custom_val(handle_), &handle, sizeof(handle));
    CAMLreturn(Val_unit);
}

CAMLprim value wrap_pcap_inject(value handle_, value str_)
{
    CAMLparam2(handle_, str_);

    pcap_t *const handle = Pcap_val(handle_);
    if (! handle) caml_failwith("Pcap handle has been closed");

    // A copy, since the string may move while the runtime is released:
    size_t size = caml_string_length(str_); // believed to be faster than strlen()
    char *str = malloc(size);
    if (! str) caml_raise_out_of_memory();
    memcpy(str, String_val(str_), size);

    // A blocking handle may wait here for the kernel to take the frame:
    caml_release_runtime_system();
    int const res = pcap_inject(handle, str, size);
    caml_acquire_runtime_system();
    free(str);

    if (PCAP_ERROR == res) caml_failwith(pcap_geterr(handle));

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_pcap_unsent(value handle_)
{
    CAMLparam1(handle_);
    pcap_t *const handle = Pcap_val(handle_);
    if (! handle) caml_failwith("Pcap handle has been closed");

    int unsent = 0;
#   ifdef SIOCOUTQ
    if (0 != ioctl(pcap_fileno(handle), SIOCOUTQ, &unsent))
        caml_failwith(strerror(errno));
#   endif

    CAMLreturn(Val_int(unsent));
}

CAMLprim value wrap_pcap_read(value timeout_, value handle_)
{
    CAMLparam2(timeout_, handle_);
    pcap_t *const handle = Pcap_val(handle_);
    if (! handle) caml_failwith("Pcap handle has been closed");
    double const timeout =
        Is_block(timeout_) ? Double_val(Field(timeout_, 0)) : 0.;
    bool const have_timeout = timeout > 0;

    struct pcap_pkthdr *hdr;
    u_char const *bytes;
    caml_release_runtime_system();
retry:
    int fd = pcap_fileno(handle);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    struct timeval timeout_s;
    if (have_timeout) {
        time_t const sec = timeout;
        suseconds_t const usec = (timeout - (double)sec) * 1e6;
        timeout_s.tv_sec = sec;
        timeout_s.tv_usec = usec;
    };
    int s = select(fd + 1, &set, NULL, NULL, have_timeout ? &timeout_s : NULL);
    if (s < 0) {
        int const errno_ = errno;
        caml_acquire_runtime_system();
        if (EBADF == errno_) {
            // The file was closed while in select
            caml_raise_end_of_file();
        }
        caml_failwith(strerror(errno));
    } else if (s == 0) {
        // Timeout: return
        caml_acquire_runtime_system();
        caml_raise_not_found();
    } else switch (pcap_next_ex(handle, &hdr, &bytes)) {
        case 1: // Ok
            caml_acquire_runtime_system();
            break;
        case 0: // Nothing?!
            /* Retry automatically in case of timeout, to avoid acquiring
             * and releasing the giant lock. */
            if (! have_timeout) goto retry;
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
    memcpy((char *)String_val(pkt), bytes, hdr->caplen);
    // caml_alloc_string already placed a nul terminator at the end

    // tv_usec holds nanoseconds when the handle has that precision:
    double const subsec =
        pcap_get_tstamp_precision(handle) == PCAP_TSTAMP_PRECISION_NANO ?
            1e-9 : 1e-6;
    ts = caml_copy_double(hdr->ts.tv_sec + (double)hdr->ts.tv_usec * subsec);

    result = caml_alloc_tuple(4);
    Field(result, 0) = ts;
    Field(result, 1) = Val_int(hdr->caplen);
    Field(result, 2) = Val_int(hdr->len);
    Field(result, 3) = pkt;

    CAMLreturn(result);
}
