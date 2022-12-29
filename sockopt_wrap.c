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
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/memory.h>

CAMLprim value wrap_set_ttl(value fd_, value ttl_)
{
    CAMLparam2(fd_, ttl_);
    int fd = Int_val(fd_);
    int ttl = Int_val(ttl_);
    char errbuf[2048];

    if (0 != setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl)) {
        snprintf(errbuf, sizeof errbuf, "Cannot setsockopt(): %s", strerror(errno));
        caml_failwith(errbuf);
    }

    CAMLreturn(Val_unit);
}

CAMLprim value wrap_set_tos(value fd_, value tos_)
{
    CAMLparam2(fd_, tos_);
    int fd = Int_val(fd_);
    int tos = Int_val(tos_);
    char errbuf[2048];

    if (0 != setsockopt(fd, IPPROTO_IP, IP_TTL, &tos, sizeof tos)) {
        snprintf(errbuf, sizeof errbuf, "Cannot setsockopt(): %s", strerror(errno));
        caml_failwith(errbuf);
    }

    CAMLreturn(Val_unit);
}
