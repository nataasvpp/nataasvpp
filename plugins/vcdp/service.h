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
#ifndef __included_vcdp_service_h__
#define __included_vcdp_service_h__
#include <vlib/vlib.h>
#include <vcdp/common.h>

#define foreach_vcdp_service                                                  \
  _ (DROP, "vcdp-drop", 0)                                                    \
  _ (NAT_EARLY_REWRITE, "vcdp-nat-early-rewrite", 1)                          \
  _ (L4_LIFECYCLE, "vcdp-l4-lifecycle", 2)                                    \
  _ (TCP_CHECK, "vcdp-tcp-check", 3)                                          \
  _ (NAT_SLOWPATH, "vcdp-nat-output", 4)                                      \
  _ (NAT_LATE_REWRITE, "vcdp-nat-late-rewrite", 5)                            \
  _ (GENEVE_OUTPUT, "vcdp-geneve-output", 6)                                  \
  _ (DUMMY_DOT1Q_OUTPUT, "vcdp-dummy-dot1q-output", 7)

enum
{
#define _(x, y, z) VCDP_SERVICE_##x = z,
  foreach_vcdp_service
#undef _
    VCDP_SERVICE_N
};

static_always_inline void
vcdp_next (vlib_buffer_t *b, u16 *next_index)
{
  u32 bmp = vcdp_buffer (b)->service_bitmap;
  u8 first = __builtin_ffs (bmp);
  ASSERT (first != 0);
  *next_index = (first - 1) + VCDP_SERVICE_DROP;
  vcdp_buffer (b)->service_bitmap ^= 1 << (first - 1);
}

#endif //__included_service_h__