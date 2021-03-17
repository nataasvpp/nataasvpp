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
#include <vcdp/common.h>
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

#define foreach_vcdp_geneve_input_next	_ (LOOKUP, "vcdp-lookup")
#define foreach_vcdp_geneve_input_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) VCDP_GENEVE_INPUT_ERROR_##sym,
  foreach_vcdp_geneve_input_error
#undef _
    VCDP_GENEVE_INPUT_N_ERROR,
} vcdp_geneve_input_error_t;

static char *vcdp_geneve_input_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_geneve_input_error
#undef _
};

typedef enum
{
#define _(s, n) VCDP_GENEVE_INPUT_NEXT_##s,
  foreach_vcdp_geneve_input_next
#undef _
    VCDP_GENEVE_INPUT_N_NEXT
} vcdp_geneve_input_next_t;

static_always_inline uword
vcdp_geneve_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  /*
   * use VNI as tenant ID
   * tenant_id -> tenant index
   * drop unknown tenants
   * store tenant_id into opaque1
   * advance current data to beginning of IP packet
   */
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b[0]);
      udp_header_t *udp;
      u32 *gnv;
      u32 tenant_id;
      clib_bihash_kv_8_8_t kv = {};
      u16 off = 0;
      if (ip4->protocol != IP_PROTOCOL_UDP)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}
      off += ip4_header_bytes (ip4);
      udp = (udp_header_t *) (b[0]->data + b[0]->current_data + off);
      if (udp->dst_port != 0xC117)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}
      off += sizeof (udp[0]);
      gnv = (u32 *) (b[0]->data + b[0]->current_data + off);

      /* Extract VNI */
      tenant_id = clib_net_to_host_u32 (gnv[1]) >> 8;
      kv.key = (u64) tenant_id;
      if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
	{
	  /* Not found */
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}

      /* Store tenant_id as flow_id (to simplify the future lookup) */
      b[0]->flow_id = tenant_id;
      vcdp_buffer (b[0])->tenant_index = kv.value;
      current_next[0] = VCDP_GENEVE_INPUT_NEXT_LOOKUP;
      off +=
	8 /* geneve header no options */ + 14 /* ethernet header, no tag*/;
      vlib_buffer_advance (b[0], off);
    end_of_packet:
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (vcdp_geneve_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_geneve_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (vcdp_geneve_input_node) = {
  .name = "vcdp-geneve-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_geneve_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_geneve_input_error_strings),
  .error_strings = vcdp_geneve_input_error_strings,
  .n_next_nodes = VCDP_GENEVE_INPUT_N_NEXT,
  .next_nodes = {
          [VCDP_GENEVE_INPUT_NEXT_LOOKUP] = "vcdp-lookup",
  },
};

VNET_FEATURE_INIT (vcdp_geneve_input_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "vcdp-geneve-input",
};
