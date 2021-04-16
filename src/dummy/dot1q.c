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
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} vcdp_dummy_dot1q_input_trace_t;

static u8 *
format_vcdp_dummy_dot1q_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (vcdp_dummy_dot1q_input_trace_t * t) =
    va_arg (*args, vcdp_dummy_dot1q_input_trace_t *);

  /*s = format (s, "snort-enq: sw_if_index %d, next index %d\n",
     t->sw_if_index, t->next_index);*/

  return s;
}

#define foreach_vcdp_dummy_dot1q_input_next  _ (LOOKUP, "vcdp-lookup")
#define foreach_vcdp_dummy_dot1q_input_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) VCDP_DUMMY_DOT1Q_ERROR_##sym,
  foreach_vcdp_dummy_dot1q_input_error
#undef _
    VCDP_DUMMY_DOT1Q_N_ERROR,
} vcdp_dummy_dot1q_input_error_t;

static char *vcdp_dummy_dot1q_input_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_dummy_dot1q_input_error
#undef _
};

typedef enum
{
#define _(s, n) VCDP_DUMMY_DOT1Q_INPUT_NEXT_##s,
  foreach_vcdp_dummy_dot1q_input_next
#undef _
    VCDP_DUMMY_DOT1Q_INPUT_N_NEXT
} vcdp_dummy_dot1q_input_next_t;

/*-----------------------------*/

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} vcdp_dummy_dot1q_output_trace_t;

static u8 *
format_vcdp_dummy_dot1q_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (vcdp_dummy_dot1q_output_trace_t * t) =
    va_arg (*args, vcdp_dummy_dot1q_output_trace_t *);

  /*s = format (s, "snort-enq: sw_if_index %d, next index %d\n",
     t->sw_if_index, t->next_index);*/

  return s;
}

#define foreach_vcdp_dummy_dot1q_output_next  _ (LOOKUP, "vcdp-lookup")
#define foreach_vcdp_dummy_dot1q_output_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) VCDP_DUMMY_DOT1Q_OUTPUT_ERROR_##sym,
  foreach_vcdp_dummy_dot1q_output_error
#undef _
    VCDP_DUMMY_DOT1Q_OUTPUT_N_ERROR,
} vcdp_dummy_dot1q_output_error_t;

static char *vcdp_dummy_dot1q_output_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_dummy_dot1q_output_error
#undef _
};

typedef enum
{
#define _(s, n) VCDP_DUMMY_DOT1Q_OUTPUT_NEXT_##s,
  foreach_vcdp_dummy_dot1q_output_next
#undef _
    VCDP_DUMMY_DOT1Q_OUTPUT_N_NEXT
} vcdp_dummy_dot1q_output_next_t;

static_always_inline void
process_one_pkt (vlib_main_t *vm, vcdp_main_t *vcdp,
		 vlib_combined_counter_main_t *cm, u32 thread_index,
		 vlib_buffer_t **b, u16 *current_next)
{
  clib_bihash_kv_8_8_t kv = { 0 };
  u8 *data = vlib_buffer_get_current (b[0]);
  u32 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
  ethernet_header_t *eth = (void *) data;
  u32 tenant_id = 0;
  u32 off = sizeof (eth[0]);
  u16 type = clib_net_to_host_u16 (eth->type);
  u16 tenant_idx;
  if (type == ETHERNET_TYPE_VLAN)
    {
      ethernet_vlan_header_t *vlan = (void *) (data + sizeof (eth[0]));
      tenant_id = clib_net_to_host_u16 (vlan->priority_cfi_and_id) & 0xfff;
      type = clib_net_to_host_u16 (vlan->type);
      off += sizeof (vlan[0]);
    }
  if (type != ETHERNET_TYPE_IP4)
    {
      vnet_feature_next_u16 (current_next, b[0]);
      return;
    }
  /* Tenant-id lookup */
  kv.key = (u64) tenant_id;
  if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
    {
      /* Not found */
      vnet_feature_next_u16 (current_next, b[0]);
      return;
    }
  b[0]->flow_id = tenant_id;
  tenant_idx = kv.value;
  vcdp_buffer (b[0])->tenant_index = tenant_idx;
  vnet_buffer (b[0])->l2_hdr_offset = b[0]->current_data;
  vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data + off;
  b[0]->flags |=
    VNET_BUFFER_F_L2_HDR_OFFSET_VALID | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  current_next[0] = VCDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP;
  vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
				   orig_len - off);
  vlib_buffer_advance (b[0], off);
}

static_always_inline uword
vcdp_dummy_dot1q_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
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
  u32 thread_index = vlib_get_thread_index ();
  vlib_combined_counter_main_t *cm =
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_INCOMING];
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left)
    {
      process_one_pkt (vm, vcdp, cm, thread_index, b, current_next);
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (vcdp_dummy_dot1q_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_dummy_dot1q_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (vcdp_dummy_dot1q_input_node) = {
  .name = "vcdp-dummy-dot1q-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_dummy_dot1q_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_dummy_dot1q_input_error_strings),
  .error_strings = vcdp_dummy_dot1q_input_error_strings,
  .n_next_nodes = VCDP_DUMMY_DOT1Q_INPUT_N_NEXT,
  .next_nodes = {
          [VCDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP] = "vcdp-lookup",
  },
};

VNET_FEATURE_INIT (vcdp_dummy_dot1q_input_feat, static) = {
  .arc_name = "device-input",
  .node_name = "vcdp-dummy-dot1q-input",
};

#define VCDP_PREFETCH_SIZE 8
VLIB_NODE_FN (vcdp_dummy_dot1q_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_combined_counter_main_t *cm =
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_OUTGOING];
  u32 thread_index = vlib_get_thread_index ();
  u16 tenant_idx[VCDP_PREFETCH_SIZE];
  u32 orig_len[VCDP_PREFETCH_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > VCDP_PREFETCH_SIZE)
    {
      word l2_len[VCDP_PREFETCH_SIZE];
      if (n_left > 2 * VCDP_PREFETCH_SIZE)
	for (int i = 0; i < VCDP_PREFETCH_SIZE; i++)
	  vlib_prefetch_buffer_header (b[0], STORE);

      for (int i = 0; i < VCDP_PREFETCH_SIZE; i++)
	{
	  orig_len[i] = vlib_buffer_length_in_chain (vm, b[i]);
	  tenant_idx[i] = vcdp_buffer (b[i])->tenant_index;
	  vlib_increment_combined_counter (cm, thread_index, tenant_idx[i], 1,
					   orig_len[i]);
	  l2_len[i] = vnet_buffer (b[i])->l3_hdr_offset;
	  l2_len[i] -= vnet_buffer (b[i])->l2_hdr_offset;
	  vlib_buffer_advance (b[i], -l2_len[i]);
	  vnet_feature_next_u16 (to_next + i, b[i]);
	}

      b += VCDP_PREFETCH_SIZE;
      to_next += VCDP_PREFETCH_SIZE;
      n_left -= VCDP_PREFETCH_SIZE;
    }
  while (n_left)
    {
      word l2_len;
      u32 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
      u16 tenant_idx = vcdp_buffer (b[0])->tenant_index;
      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
				       orig_len);
      l2_len = vnet_buffer (b[0])->l3_hdr_offset;
      l2_len -= vnet_buffer (b[0])->l2_hdr_offset;
      vlib_buffer_advance (b[0], -l2_len);
      vnet_feature_next_u16 (to_next, b[0]);

      b += 1;
      to_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}
#undef VCDP_PREFETCH_SIZE

VLIB_REGISTER_NODE (vcdp_dummy_dot1q_output_node) = {
  .name = "vcdp-dummy-dot1q-output",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_dummy_dot1q_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_dummy_dot1q_output_error_strings),
  .error_strings = vcdp_dummy_dot1q_output_error_strings,

  .sibling_of = "vcdp-dummy-dot1q-input"

};