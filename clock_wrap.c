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
#include <time.h>

#include "caml/mlvalues.h"

// Nanoseconds since 1970, as a Clock.Wall.t:
CAMLprim value wrap_clock_realtime_ns(value unit)
{
    (void)unit;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return Val_long((long)ts.tv_sec * 1000000000L + ts.tv_nsec);
}
