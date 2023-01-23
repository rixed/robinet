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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>  // for NI_MAXHOST
#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <linux/errqueue.h> // Required for some reason for sock_extended_err
#include <netinet/ip_icmp.h>    // For ICMP_DEST_UNREACH

static void fail(char const *what)
{
    char errbuf[2048];
    snprintf(errbuf, sizeof errbuf, "Cannot %s(): %s", what, strerror(errno));
    caml_failwith(errbuf);
}

static void fail_setsockopt(void)
{
    fail("setsockopt");
}

CAMLprim value wrap_set_ttl(value fd_, value ttl_)
{
    CAMLparam2(fd_, ttl_);
    int fd = Int_val(fd_);
    int ttl = Int_val(ttl_);

    if (ttl < 0 || ttl >= 256) {
        caml_invalid_argument("Invalid TTL");
    }

    if (0 != setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl))
        fail_setsockopt();

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_set_tos(value fd_, value tos_)
{
    CAMLparam2(fd_, tos_);
    int fd = Int_val(fd_);
    int tos = Int_val(tos_);

    if (0 != setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof tos))
        fail_setsockopt();

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_set_df(value fd_)
{
    CAMLparam1(fd_);
    int fd = Int_val(fd_);
    int flag = IP_PMTUDISC_PROBE;

    if (0 != setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof flag))
        fail_setsockopt();

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_set_recv_errs(value fd_, value on_)
{
    CAMLparam2(fd_, on_);
    int fd = Int_val(fd_);
    int on = Bool_val(on_);

    if (0 != setsockopt(fd, IPPROTO_IP, IP_RECVERR, &on, sizeof on))
        fail_setsockopt();

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_set_tcp_syn_count(value fd_, value cnt_)
{
    CAMLparam2(fd_, cnt_);
    int fd = Int_val(fd_);
    int cnt = Int_val(cnt_);

    if (0 != setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &cnt, sizeof cnt))
        fail_setsockopt();

    CAMLreturn(Val_unit);
}

#undef DEBUG
#ifdef DEBUG
#   include <stdio.h>  // DEBUG
#endif

extern value alloc_inet_addr(struct in_addr *inaddr);
extern value alloc_inet6_addr(struct in6_addr *inaddr);

/* Returns the last received ICMP error code for an unreachable destination,
 * and the inet_addr of the router emitting the error (optional), or raise
 * Not_found: */
CAMLprim value wrap_get_last_icmp_err(value fd_)
{
    CAMLparam1(fd_);
    CAMLlocal2(addr_, ret_);
    int fd = Int_val(fd_);

    struct sockaddr_in orig_dst;  // The original destination address of the packet that caused the error
    char buffer[2048];  // Kernel will store ICMP datagram in there (?)
    struct msghdr msg = {
        .msg_name = &orig_dst,
        .msg_namelen = sizeof orig_dst,
        .msg_iov = NULL,
        .msg_iovlen = 0,
        .msg_control = buffer,
        .msg_controllen = sizeof buffer,
        .msg_flags = 0
    };
    if (0 > recvmsg(fd, &msg, /*MSG_DONTWAIT |*/ MSG_ERRQUEUE)) {
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
#           ifdef DEBUG
            fprintf(stderr, "No ERRQUEUE message yet\n");
#           endif
            caml_raise_not_found();
        } else
            fail("recvmsg");
    }

#   ifdef DEBUG
    fprintf(stderr, "Got an error, flag=%d\n", msg.msg_flags);
#   endif

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_IP) continue;
        struct sock_extended_err *err = (struct sock_extended_err *)CMSG_DATA(cmsg);
        if (! err) continue;
#       ifdef DEBUG
        fprintf(stderr, "  err origin=%d, type=%d, code=%d\n",
                err->ee_origin, err->ee_type, err->ee_code);
#       endif
        if (err->ee_origin != SO_EE_ORIGIN_ICMP &&
            err->ee_origin != SO_EE_ORIGIN_ICMP6 &&
            err->ee_type != ICMP_DEST_UNREACH) continue;
        /* Also return the emitting IP as a Unix.inet_addr, which is
         * in an OCaml string: */
        struct sockaddr *offender = SO_EE_OFFENDER(err);
        int const family = offender->sa_family;
        switch (family) {
            case AF_INET:
                addr_ = caml_alloc_small(1, 0);
                Store_field(addr_, 0, alloc_inet_addr(
                    &((struct sockaddr_in *)offender)->sin_addr));
                break;
            case AF_INET6:
                addr_ = caml_alloc_small(1, 0);
                Store_field(addr_, 0, alloc_inet6_addr(
                    &((struct sockaddr_in6 *)offender)->sin6_addr));
                break;
            default:
                addr_ = Val_int(0); //Val_none;
        }
#       ifdef DEBUG
        if (family == AF_INET || family == AF_INET6) {
            char host[NI_MAXHOST];
            int const s =
                getnameinfo(offender,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) fail("getnameinfo");
            fprintf(stderr, "  offender: %s\n", host);
        }
#       endif
        ret_ = caml_alloc_tuple(2);
        Store_field(ret_, 0, Val_int(err->ee_code));
        Store_field(ret_, 1, addr_);
        CAMLreturn(ret_);
    }

    caml_raise_not_found();
}
