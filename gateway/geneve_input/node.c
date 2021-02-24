/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <gateway/gateway.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} vcdp_geneve_input_trace_t;

static u8 *
format_vcdp_geneve_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vcdp_geneve_input_trace_t *t = va_arg (*args, vcdp_geneve_input_trace_t *);

  s = format (s, "snort-enq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

#define foreach_vcdp_geneve_input_error _ (SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym, str) SAMPLE_ERROR_##sym,
  foreach_vcdp_geneve_input_error
#undef _
    SAMPLE_N_ERROR,
} vcdp_geneve_input_error_t;

static char *vcdp_geneve_input_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_geneve_input_error
#undef _
};

VLIB_NODE_FN (vcdp_geneve_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * use VNI as tenant ID
   * tenant_id -> tenant index
   * drop unknown tenants
   * store tenant_id into opaque1
   * advance current data to beginning of IP packet
   */
  return 0;
}

VLIB_REGISTER_NODE (vcdp_geneve_input_node) = {
  .name = "vcdp-geneve-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_geneve_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_geneve_input_error_strings),
  .error_strings = vcdp_geneve_input_error_strings,

  .n_next_nodes = 0,
};

