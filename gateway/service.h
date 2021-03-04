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

#define vcdp_bmp_to_next_index(bmp)                                           \
  (__builtin_ffs ((bmp)) + vcdp_base_next_index);

/* Next index of the last next node of vcdp-lookup which is NOT a service */
extern u8 vcdp_base_next_index;

void vcdp_service_init (vlib_main_t *vm);

#endif //__included_service_h__