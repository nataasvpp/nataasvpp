/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vcdp/common.h>
#include <vcdp/vcdp.h>

typedef struct
{

} vcdp_lookup_sp_sv_reass_trace_t;

static u8 *
format_vcdp_lookup_sp_sv_reass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (vcdp_lookup_sp_sv_reass_trace_t * t) =
    va_arg (*args, vcdp_lookup_sp_sv_reass_trace_t *);

  return s;
}

#define foreach_vcdp_lookup_sp_sv_reass_next                                  \
  _ (IP4_SVR, "ip4-sv-reassembly-custom-context")                             \
  _ (IP6_SVR, "ip6-sv-reassembly-custom-context")

enum
{
#define _(sym, str) VCDP_LOOKUP_SP_SV_REASS_NEXT_##sym,
  foreach_vcdp_lookup_sp_sv_reass_next
#undef _
    VCDP_LOOKUP_SP_SV_REASS_N_NEXT
};

#define foreach_vcdp_lookup_sp_sv_reass_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) VCDP_LOOKUP_SP_SV_REASS_ERROR_##sym,
  VCDP_LOOKUP_SP_SV_REASS_N_ERROR
#undef _
} vcdp_lookup_sp_sv_reass_error_t;

static char *vcdp_lookup_sp_sv_reass_error_strings[] = {
#define _(sym, str) str,
  foreach_vcdp_lookup_sp_sv_reass_error
#undef _
};

static_always_inline u32
vcdp_lookup_sp_sv_reass_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame, bool is_ip6)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 aux_data[VLIB_FRAME_SIZE], *a;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  a = aux_data;
  // TODO: prefetch + 4-loop
  while (n_left)
    {
      a[0] = b[0]->flow_id;

      /* Save the tenant index */
      vcdp_buffer2 (b[0])->tenant_index = vcdp_buffer (b[0])->tenant_index;
      vcdp_buffer2 (b[0])->flags = VCDP_BUFFER_FLAG_REASSEMBLED;

      vnet_buffer (b[0])->ip.reass.next_index =
	is_ip6 ? vcdp->ip6_sv_reass_next_index : vcdp->ip4_sv_reass_next_index;
      b += 1;
      a += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_single_next_with_aux (
    vm, node, from, aux_data,
    is_ip6 ? VCDP_LOOKUP_SP_SV_REASS_NEXT_IP6_SVR :
		   VCDP_LOOKUP_SP_SV_REASS_NEXT_IP4_SVR,
    frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (vcdp_lookup_ip4_sp_sv_reass)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_lookup_sp_sv_reass_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (vcdp_lookup_ip4_sp_sv_reass) = {
  .name = "vcdp-lookup-ip4-sp-sv-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_lookup_sp_sv_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_lookup_sp_sv_reass_error_strings),
  .error_strings = vcdp_lookup_sp_sv_reass_error_strings,
  .next_nodes = {
#define _(sym, str) [VCDP_LOOKUP_SP_SV_REASS_NEXT_##sym] = str,
  foreach_vcdp_lookup_sp_sv_reass_next
#undef _ 
  },
  .n_next_nodes = VCDP_LOOKUP_SP_SV_REASS_N_NEXT,
};

VLIB_NODE_FN (vcdp_lookup_ip6_sp_sv_reass)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_lookup_sp_sv_reass_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (vcdp_lookup_ip6_sp_sv_reass) = {
  .name = "vcdp-lookup-ip6-sp-sv-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_lookup_sp_sv_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_lookup_sp_sv_reass_error_strings),
  .error_strings = vcdp_lookup_sp_sv_reass_error_strings,
  .next_nodes = {
#define _(sym, str) [VCDP_LOOKUP_SP_SV_REASS_NEXT_##sym] = str,
  foreach_vcdp_lookup_sp_sv_reass_next
#undef _ 
  },
  .n_next_nodes = VCDP_LOOKUP_SP_SV_REASS_N_NEXT,
};