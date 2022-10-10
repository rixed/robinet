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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
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
 * Reading/Writing packets from/to sockets bound to a TAP device
 */

CAMLprim value wrap_tap_open(value ifname_)
{
    CAMLparam1(ifname_);
    char const *const ifname = String_val(ifname_);

    printf("tap_wrap: opening iface %s\n", ifname);

    int sock;
    char errbuf[2048];
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        snprintf(errbuf, sizeof errbuf, "Cannot socket(): %s", strerror(errno));
        caml_failwith(errbuf);
    }

    struct ifreq ifreq;
    snprintf(ifreq.ifr_name, sizeof ifreq.ifr_name, ifname);
    if (-1 == ioctl(sock, SIOCGIFINDEX, &ifreq)) {
        snprintf(errbuf, sizeof errbuf, "Cannot ioctl(): %s", strerror(errno));
        (void)close(sock);
        caml_failwith(errbuf);
    }

    struct sockaddr_ll saddr;
    bzero(&saddr, sizeof saddr);
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifreq.ifr_ifindex;
    saddr.sll_pkttype = PACKET_HOST;

    if (-1 == bind(sock, (struct sockaddr *)&saddr, sizeof saddr)) {
        snprintf(errbuf, sizeof errbuf, "Cannot bind(): %s", strerror(errno));
        (void)close(sock);
        caml_failwith(errbuf);
    }

    CAMLreturn(Val_int(sock));
}

CAMLprim value wrap_tap_read(value sock_)
{
    CAMLparam1(sock_);
    int const sock = Int_val(sock_);

    printf("tap_wrap: reading from socket\n");

    char buf[2048];
retry:
    caml_release_runtime_system();
    int const sz = recvfrom(sock, buf, sizeof buf, 0, NULL, NULL);
    caml_acquire_runtime_system();
    if (sz < 0) {
        if (errno == EINTR) goto retry;
        snprintf(buf, sizeof buf, "Cannot recvfrom(): %s", strerror(errno));
        caml_failwith(buf);
    }

    printf("tap_wrap: read %d bytes\n", sz);

    CAMLlocal1(pkt);
    pkt = caml_alloc_string(sz);
    memcpy(String_val(pkt), buf, sz);
    Byte(pkt, sz+1) = 0;

    CAMLreturn(pkt);
}
