/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_service_h__
#define __included_service_h__
#include <vlib/vlib.h>
#include <vcdp/common.h>

/* clang-format off */
#define foreach_service                         \
  _(DROP, "vcdp-drop", 0)                       \
  _(TCP_CHECK, "vcdp-tcp-checks", 1)            \
  _(GENEVE_OUTPUT, "vcdp-geneve-output", 2)
/* clang-format on */
enum
{
#define _(x, y, z) VCDP_SERVICE_##x = z,
  foreach_service
#undef _
    VCDP_SERVICE_N
};

/* Next index of the first next node of vcdp-lookup which is a service */
extern u8 vcdp_base_next_index;

static_always_inline void
vcdp_next (vlib_buffer_t *b, u16 *next_index)
{
  u32 bmp = vcdp_buffer (b)->service_bitmap;
  u8 first = __builtin_ffs (bmp);
  ASSERT (first != 0);
  *next_index = (first - 1) + vcdp_base_next_index;
  vcdp_buffer (b)->service_bitmap ^= 1 << (first - 1);
}

clib_error_t *vcdp_service_init (vlib_main_t *vm);

#endif //__included_service_h__