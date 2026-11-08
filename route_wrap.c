// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2026, Cedric Cellier
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
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#ifdef __linux__

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

CAMLprim value wrap_route_available(value unit_)
{
    (void)unit_;
    return Val_true;
}

static void fail(char const *what, int err)
{
    char errbuf[256];
    snprintf(errbuf, sizeof errbuf, "%s: %s", what, strerror(err));
    caml_failwith(errbuf);
}

/* Shared by all lookups, which are serialized by not releasing the OCaml
 * runtime lock. The kernel answers while handling the send, so this blocks
 * for no longer than the lookup. */
static int route_socket(void)
{
    static int fd = -1;
    if (fd < 0) {
        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) fail("Cannot open a netlink socket", errno);
    }
    return fd;
}

static void add_attr(struct nlmsghdr *h, int type, void const *data, size_t len)
{
    struct rtattr *a = (struct rtattr *)((char *)h + NLMSG_ALIGN(h->nlmsg_len));
    a->rta_type = type;
    a->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(a), data, len);
    h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(a->rta_len);
}

/* [wrap_route_lookup dst oif]: the route the kernel picks towards [dst], the
 * 4 or 16 bytes of an address, restricted to the interface named [oif] unless
 * empty, as (the RTN_* type, the outgoing interface's name, the gateway's
 * bytes or else ""). Raises Failure if there is none. */
CAMLprim value wrap_route_lookup(value dst_, value oif_)
{
    CAMLparam2(dst_, oif_);
    CAMLlocal3(ret_, name_, gw_);
    static unsigned seq;

    size_t const dst_len = caml_string_length(dst_);
    if (dst_len != 4 && dst_len != 16)
        caml_invalid_argument("wrap_route_lookup");

    struct {
        struct nlmsghdr hdr;
        struct rtmsg rtm;
        char attrs[64];
    } req;
    memset(&req, 0, sizeof req);
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof req.rtm);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_seq = ++seq;
    req.rtm.rtm_family = dst_len == 4 ? AF_INET : AF_INET6;
    req.rtm.rtm_dst_len = dst_len * 8;
    add_attr(&req.hdr, RTA_DST, String_val(dst_), dst_len);
    if (caml_string_length(oif_) > 0) {
        unsigned const oif = if_nametoindex(String_val(oif_));
        if (0 == oif) fail(String_val(oif_), errno);
        add_attr(&req.hdr, RTA_OIF, &oif, sizeof oif);
    }

    int const fd = route_socket();
    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        fail("Cannot ask for a route", errno);

    char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
    for (;;) {
        ssize_t len = recv(fd, buf, sizeof buf, 0);
        if (len < 0) fail("Cannot read a route", errno);
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf;
             NLMSG_OK(h, (size_t)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != req.hdr.nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr const *e = NLMSG_DATA(h);
                fail("Route lookup", -e->error);
            }
            if (h->nlmsg_type != RTM_NEWROUTE) continue;

            struct rtmsg const *rtm = NLMSG_DATA(h);
            unsigned oif = 0;
            void const *gw = NULL;
            size_t gw_len = 0;
            int attrs_len = RTM_PAYLOAD(h);
            for (struct rtattr const *a = RTM_RTA(rtm);
                 RTA_OK(a, attrs_len);
                 a = RTA_NEXT(a, attrs_len)) {
                switch (a->rta_type) {
                    case RTA_OIF:
                        oif = *(unsigned const *)RTA_DATA(a);
                        break;
                    case RTA_GATEWAY:
                        gw = RTA_DATA(a);
                        gw_len = RTA_PAYLOAD(a);
                        break;
                    case RTA_VIA: {
                        /* A gateway of the other family: */
                        struct rtvia const *via = RTA_DATA(a);
                        gw = via->rtvia_addr;
                        gw_len = RTA_PAYLOAD(a) - sizeof via->rtvia_family;
                        break;
                    }
                }
            }
            char name[IF_NAMESIZE] = "";
            if (oif && ! if_indextoname(oif, name))
                fail("Cannot name the interface of a route", errno);
            name_ = caml_copy_string(name);
            gw_ = caml_alloc_initialized_string(gw_len, gw ? gw : "");
            ret_ = caml_alloc_tuple(3);
            Store_field(ret_, 0, Val_int(rtm->rtm_type));
            Store_field(ret_, 1, name_);
            Store_field(ret_, 2, gw_);
            CAMLreturn(ret_);
        }
    }
}

#else // __linux__

CAMLprim value wrap_route_available(value unit_)
{
    (void)unit_;
    return Val_false;
}

CAMLprim value wrap_route_lookup(value dst_, value oif_)
{
    CAMLparam2(dst_, oif_);
    caml_failwith("Asking the kernel for routes works only on Linux");
    CAMLreturn(Val_unit);
}

#endif // __linux__
