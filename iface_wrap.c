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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

CAMLprim value wrap_addresses_of_iface(value ifname_)
{
    CAMLparam1(ifname_);
    CAMLlocal3(lst, str, cell);
    char const *const ifname = String_val(ifname_);

    struct ifaddrs *ifa_head;
    char errbuf[2048];
    if (0 != getifaddrs(&ifa_head)) {
        snprintf(errbuf, sizeof errbuf, "Cannot getifaddrs(): %s", strerror(errno));
        caml_failwith(errbuf);
    }

    lst = Val_int(0);   // empty list constructor
    for (struct ifaddrs const *ifa = ifa_head; ifa; ifa = ifa->ifa_next) {
        if (0 != strcmp(ifname, ifa->ifa_name)) continue;
        // Collect only ip addresses:
        int const family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        char host[NI_MAXHOST];
        int const s =
            getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                      sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            snprintf(errbuf, sizeof errbuf, "Cannot getnameinfo(): %s", gai_strerror(s));
            caml_failwith(errbuf);
        }

        str = caml_copy_string(host);
        cell = caml_alloc(2, 0);
        Store_field(cell, 1, lst);
        Store_field(cell, 0, str);
        lst = cell;
    }

    freeifaddrs(ifa_head);

    CAMLreturn(lst);
}
