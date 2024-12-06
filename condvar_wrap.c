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
#include <pthread.h>
#include <errno.h>
#include <stdio.h>

#include "caml/alloc.h"
#include "caml/fail.h"
#include "caml/memory.h"
#include "caml/mlvalues.h"
#include "caml/signals.h"

typedef pthread_cond_t *condvar;
#define Condvar_val(v) (*(condvar *)Data_custom_val(v))

typedef pthread_mutex_t *mutex;
#define Mutex_val(v) (*((mutex *)Data_custom_val(v)))

CAMLprim value caml_condition_timedwait(value cond_, value mut_, value timeo_)
{
    CAMLparam3(cond_, mut_, timeo_);

    condvar cond = Condvar_val(cond_);
    mutex mut = Mutex_val(mut_);
    double const timeo = Double_val(timeo_);
    /* Note: time_t is "an integer type" according to POSIX, whereas suseconds_t
     * is a signed integer. */
    time_t const sec = (time_t)timeo;
    suseconds_t const nsec = (suseconds_t)((timeo - (double)sec) * 1e9);
    struct timespec const abstime = { .tv_sec = sec, .tv_nsec = nsec };

    caml_enter_blocking_section();
    int ret = pthread_cond_timedwait(cond, mut, &abstime);
    caml_leave_blocking_section();

    if (ret != 0 && ret != ETIMEDOUT) {
        switch (ret) {
            case ENOTRECOVERABLE:
                caml_raise_sys_error(caml_copy_string("ENOTRECOVERABLE"));
                break;
            case EOWNERDEAD:
                caml_raise_sys_error(caml_copy_string("EOWNERDEAD"));
                break;
            case EPERM:
                caml_raise_sys_error(caml_copy_string("EPERM"));
                break;
            case EINVAL:
                caml_raise_sys_error(caml_copy_string("EINVAL"));
                break;
        }

        char err[200];
        snprintf(err, 200-1, "Unknown error %d", ret);
        caml_raise_sys_error(caml_copy_string(err));
    }

    CAMLlocal1(v);
    v = ret == 0 ? Val_false : Val_true;
    CAMLreturn(v);
}
