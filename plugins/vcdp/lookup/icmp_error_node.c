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
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "lookup_inlines.h"

#define foreach_vcdp_lookup_icmp_error                                        \
  _ (NO_SESSION, "no session")                                                \
  _ (INVALID_INNER_PKT, "invalid inner packet")

typedef enum
{
#define _(sym, str) VCDP_LOOKUP_ICMP_ERROR_##sym,
  foreach_vcdp_lookup_icmp_error
#undef _
    VCDP_LOOKUP_ICMP_ERROR_N_ERROR,
} vcdp_lookup_error_t;

static char *vcdp_lookup_icmp_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_lookup_icmp_error
#undef _
};

#define foreach_vcdp_lookup_icmp_next _ (DROP, "error-drop")

typedef enum
{
#define _(a, b) VCDP_LOOKUP_ICMP_NEXT_##a,
  foreach_vcdp_lookup_icmp_next
#undef _
    VCDP_LOOKUP_ICMP_N_NEXT
} vcdp_lookup_icmp_next_t;

typedef struct
{

} vcdp_lookup_icmp_trace_t;

typedef struct
{

} vcdp_handoff_icmp_trace_t;

static u8 *
format_vcdp_lookup_icmp_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_lookup_icmp_trace_t __clib_unused *t =
    va_arg (*args, vcdp_lookup_icmp_trace_t *);

  return s;
}

static_always_inline uword
vcdp_lookup_icmp_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, u8 is_ipv6)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);

  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 *bi = from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  i16 current_data[VLIB_FRAME_SIZE], *cd = current_data;
  VCDP_SESSION_IP46_KEYS_TYPE (VLIB_FRAME_SIZE) keys;
  vcdp_session_ip4_key_t *k4 = keys.keys4;
  vcdp_session_ip6_key_t *k6 = keys.keys6;
  u64 lookup_vals[VLIB_FRAME_SIZE], *lv = lookup_vals;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  i16 l4_hdr_off[VLIB_FRAME_SIZE], *l4o = l4_hdr_off;
  u16 local_next_indices[VLIB_FRAME_SIZE], *lni = local_next_indices;
  u32 local_buffer_indices[VLIB_FRAME_SIZE], *lbi = local_buffer_indices;
  u32 handoff_buffer_indices[VLIB_FRAME_SIZE], *hbi = handoff_buffer_indices;
  u16 handoff_thread_indices[VLIB_FRAME_SIZE], *hti = handoff_thread_indices;
  bool local_has_session[VLIB_FRAME_SIZE], *lhs = local_has_session;

  vlib_get_buffers (vm, from, bufs, n_left);

  if (!is_ipv6)
    {
      while (n_left)
	{
	  /* Advance the current buffer */
	  cd[0] = b[0]->current_data;
	  b[0]->current_data = vnet_buffer (b[0])->l4_hdr_offset +
			       8 /* ICMP header + unused field */;
	  calc_key_v4 (b[0], b[0]->flow_id, k4, lv, h, l4o, 1);
	  b[0]->current_data = cd[0];

	  cd += 1;
	  b += 1;
	  k4 += 1;
	  lv += 1;
	  h += 1;
	  l4o += 1;
	  n_left -= 1;
	}
    }
  else
    {
      while (n_left)
	{
	  /* Advance the current buffer */
	  cd[0] = b[0]->current_data;
	  b[0]->current_data = vnet_buffer (b[0])->l4_hdr_offset +
			       8 /* ICMP header + unused field */;
	  calc_key_v6 (b[0], b[0]->flow_id, k6, lv, h, l4o, 1);
	  b[0]->current_data = cd[0];

	  cd += 1;
	  b += 1;
	  k6 += 1;
	  lv += 1;
	  h += 1;
	  l4o += 1;
	  n_left -= 1;
	}
    }
  /* Perform the lookup */
  b = bufs;
  bi = from;
  k4 = keys.keys4;
  k6 = keys.keys6;
  lv = lookup_vals;
  h = hashes;
  l4o = l4_hdr_off;

  n_left = frame->n_vectors;

  if (!is_ipv6)
    {
      while (n_left)
	{
	  uword flow_thread_index;
	  u16 tenant_index;
	  vcdp_tenant_t *tenant;
	  clib_bihash_kv_24_8_t kv4;

	  if (lv[0] & VCDP_LV_TO_SP)
	    {
	      vlib_node_increment_counter (
		vm, node->node_index, VCDP_LOOKUP_ICMP_ERROR_INVALID_INNER_PKT,
		1);
	      lbi[0] = bi[0];
	      lni[0] = VCDP_LOOKUP_ICMP_NEXT_DROP;
	      lhs[0] = false;

	      lbi += 1;
	      lni += 1;
	      lhs += 1;
	      goto next_pkt4;
	    }

	  clib_memcpy (&kv4.key, k4, 24);
	  if (clib_bihash_search_inline_with_hash_24_8 (&vcdp->table4, h[0],
							&kv4))
	    {
	      /* TODO: not drop? */
	      vlib_node_increment_counter (
		vm, node->node_index, VCDP_LOOKUP_ICMP_ERROR_NO_SESSION, 1);
	      lbi[0] = bi[0];
	      lni[0] = VCDP_LOOKUP_ICMP_NEXT_DROP;
	      lhs[0] = false;

	      lbi += 1;
	      lni += 1;
	      lhs += 1;
	      goto next_pkt4;
	    }
	  else
	    {
	      lv[0] ^= kv4.value;
	    }

	  flow_thread_index = vcdp_thread_index_from_lookup (lv[0]);

	  if (thread_index != flow_thread_index)
	    {
	      hbi[0] = bi[0];
	      hti[0] = flow_thread_index;

	      hbi += 1;
	      hti += 1;
	      goto next_pkt4;
	    }
	  /* Flip last bit of flow index because the error goes into the
	   * opposite direction */
	  b[0]->flow_id = (lv[0] & (~(u32) 0)) ^ 0x1;

	  tenant_index = vcdp_buffer (b[0])->tenant_index;
	  tenant = vcdp_tenant_at_index (vcdp, tenant_index);

	  lbi[0] = bi[0];
	  lni[0] = tenant->icmp4_lookup_next;
	  lhs[0] = true;

	  lbi += 1;
	  lni += 1;
	  lhs += 1;

	next_pkt4:

	  b += 1;
	  bi += 1;
	  k4 += 1;
	  lv += 1;
	  h += 1;
	  l4o += 1;
	  n_left -= 1;
	}
    }
  else
    {
      while (n_left)
	{
	  uword flow_thread_index;
	  u16 tenant_index;
	  vcdp_tenant_t *tenant;
	  clib_bihash_kv_48_8_t kv6;

	  if (lv[0] & VCDP_LV_TO_SP)
	    {
	      vlib_node_increment_counter (
		vm, node->node_index, VCDP_LOOKUP_ICMP_ERROR_INVALID_INNER_PKT,
		1);
	      lbi[0] = bi[0];
	      lni[0] = VCDP_LOOKUP_ICMP_NEXT_DROP;
	      lhs[0] = false;

	      lbi += 1;
	      lni += 1;
	      lhs += 1;
	      goto next_pkt6;
	    }

	  clib_memcpy (&kv6.key, k6, 48);
	  if (clib_bihash_search_inline_with_hash_48_8 (&vcdp->table6, h[0],
							&kv6))
	    {
	      /* TODO: not drop? */
	      vlib_node_increment_counter (
		vm, node->node_index, VCDP_LOOKUP_ICMP_ERROR_NO_SESSION, 1);
	      lbi[0] = bi[0];
	      lni[0] = VCDP_LOOKUP_ICMP_NEXT_DROP;
	      lhs[0] = false;

	      lbi += 1;
	      lni += 1;
	      lhs += 1;
	      goto next_pkt6;
	    }
	  else
	    {
	      lv[0] ^= kv6.value;
	    }

	  flow_thread_index = vcdp_thread_index_from_lookup (lv[0]);

	  if (thread_index != flow_thread_index)
	    {
	      hbi[0] = bi[0];
	      hti[0] = flow_thread_index;

	      hbi += 1;
	      hti += 1;
	      goto next_pkt6;
	    }
	  /* Flip last bit of flow index because the error goes into the
	   * opposite direction */
	  b[0]->flow_id = (lv[0] & (~(u32) 0)) ^ 0x1;

	  tenant_index = vcdp_buffer (b[0])->tenant_index;
	  tenant = vcdp_tenant_at_index (vcdp, tenant_index);

	  lbi[0] = bi[0];
	  lni[0] = tenant->icmp6_lookup_next;
	  lhs[0] = true;

	  lbi += 1;
	  lni += 1;
	  lhs += 1;

	next_pkt6:

	  b += 1;
	  bi += 1;
	  k4 += 1;
	  lv += 1;
	  h += 1;
	  l4o += 1;
	  n_left -= 1;
	}
    }

  if (lbi - local_buffer_indices)
    {
      uword n = lbi - local_buffer_indices;
      uword n_left_local = n;
      lbi = local_buffer_indices;
      lhs = local_has_session;
      vlib_get_buffers (vm, lbi, bufs, n);
      b = bufs;
      while (n_left_local)
	{
	  vcdp_session_t *session;
	  if (lhs[0])
	    {
	      session = vcdp_session_at_index (ptd, b[0]->flow_id << 1);
	      vcdp_buffer (b[0])->tenant_index = session->tenant_idx;
	    }
	  lbi += 1;
	  lhs += 1;
	  n_left_local -= 1;
	}
      vlib_buffer_enqueue_to_next (vm, node, local_buffer_indices,
				   local_next_indices, n);
    }

  if (hbi - handoff_buffer_indices)
    vlib_buffer_enqueue_to_thread (
      vm, node,
      is_ipv6 ? vcdp->icmp6_error_frame_queue_index :
		      vcdp->icmp4_error_frame_queue_index,
      handoff_buffer_indices, handoff_thread_indices,
      hbi - handoff_buffer_indices, 1);

  return frame->n_vectors;
}

VLIB_NODE_FN (vcdp_lookup_ip4_icmp_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_lookup_icmp_inline (vm, node, frame, 0 /* is ipv6 */);
}

VLIB_NODE_FN (vcdp_lookup_ip6_icmp_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_lookup_icmp_inline (vm, node, frame, 1 /* is ipv6 */);
}

VLIB_REGISTER_NODE (vcdp_lookup_ip4_icmp_node) = {
  .name = "vcdp-lookup-ip4-icmp",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_lookup_icmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_lookup_icmp_error_strings),
  .error_strings = vcdp_lookup_icmp_error_strings,
  .next_nodes = {
#define _(a, b) [VCDP_LOOKUP_ICMP_NEXT_##a] = (b),
          foreach_vcdp_lookup_icmp_next
#undef _
  },
  .n_next_nodes = VCDP_LOOKUP_ICMP_N_NEXT
};

VLIB_REGISTER_NODE (vcdp_lookup_ip6_icmp_node) = {
  .name = "vcdp-lookup-ip6-icmp",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_lookup_icmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_lookup_icmp_error_strings),
  .error_strings = vcdp_lookup_icmp_error_strings,
    .next_nodes = {
#define _(a, b) [VCDP_LOOKUP_ICMP_NEXT_##a] = (b),
          foreach_vcdp_lookup_icmp_next
#undef _
  },
  .n_next_nodes = VCDP_LOOKUP_ICMP_N_NEXT
};