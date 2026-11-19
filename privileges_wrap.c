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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>

/* Both fit in the first word of the capability sets: */
static uint32_t const net_caps = (1U << CAP_NET_ADMIN) | (1U << CAP_NET_RAW);

/* Bits of the value [wrap_pass_on_net_caps] returns, telling what
 * [wrap_restore_net_caps] has to take back: */
#define AMBIENT_SHIFT 0
#define INHERITABLE_SHIFT 32

static int get_caps(struct __user_cap_header_struct *hdr,
                    struct __user_cap_data_struct data[2])
{
    hdr->version = _LINUX_CAPABILITY_VERSION_3;
    hdr->pid = 0;
    return syscall(SYS_capget, hdr, data);
}

CAMLprim value wrap_is_secure(value unit)
{
    CAMLparam1(unit);
    CAMLreturn(Val_bool(getauxval(AT_SECURE) != 0));
}

CAMLprim value wrap_clearenv(value unit)
{
    CAMLparam1(unit);
    if (0 != clearenv()) caml_failwith("clearenv");
    CAMLreturn(Val_unit);
}

CAMLprim value wrap_has_net_admin(value unit)
{
    CAMLparam1(unit);
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    CAMLreturn(Val_bool(0 == get_caps(&hdr, data) &&
                        (data[0].effective & (1U << CAP_NET_ADMIN))));
}

/* Make the network capabilities of the calling thread ambient, which needs
 * them inheritable too. Best effort: what cannot be passed on is not. */
CAMLprim value wrap_pass_on_net_caps(value unit)
{
    CAMLparam1(unit);
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    int64_t done = 0;
    if (0 != get_caps(&hdr, data)) CAMLreturn(Val_long(0));
    uint32_t const caps = data[0].permitted & net_caps;
    uint32_t const added = caps & ~data[0].inheritable;
    if (added) {
        data[0].inheritable |= added;
        if (0 != syscall(SYS_capset, &hdr, data)) CAMLreturn(Val_long(0));
        done |= (int64_t)added << INHERITABLE_SHIFT;
    }
    for (int cap = 0; cap < 32; cap++) {
        if (! (caps & (1U << cap))) continue;
        if (0 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) &&
            0 == prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0))
            done |= (int64_t)1 << (cap + AMBIENT_SHIFT);
    }
    CAMLreturn(Val_long(done));
}

/* Take back what [wrap_pass_on_net_caps] did, as told by what it returned: */
CAMLprim value wrap_restore_net_caps(value done_)
{
    CAMLparam1(done_);
    int64_t const done = Long_val(done_);
    uint32_t const ambient = (uint32_t)(done >> AMBIENT_SHIFT);
    uint32_t const added = (uint32_t)(done >> INHERITABLE_SHIFT);
    for (int cap = 0; cap < 32; cap++)
        if (ambient & (1U << cap))
            (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0);
    if (added) {
        struct __user_cap_header_struct hdr;
        struct __user_cap_data_struct data[2];
        if (0 == get_caps(&hdr, data)) {
            data[0].inheritable &= ~added;
            (void)syscall(SYS_capset, &hdr, data);
        }
    }
    CAMLreturn(Val_unit);
}
