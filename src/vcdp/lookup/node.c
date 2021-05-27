/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>

#define foreach_vcdp_lookup_error                                             \
  _ (MISS, "flow miss")                                                       \
  _ (LOCAL, "local flow")                                                     \
  _ (REMOTE, "remote flow")                                                   \
  _ (COLLISION, "hash add collision")                                         \
  _ (CON_DROP, "handoff drop")

typedef enum
{
#define _(sym, str) VCDP_LOOKUP_ERROR_##sym,
  foreach_vcdp_lookup_error
#undef _
    VCDP_LOOKUP_N_ERROR,
} vcdp_lookup_error_t;

static char *vcdp_lookup_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_lookup_error
#undef _
};

#define foreach_vcdp_handoff_error _ (NOERROR, "no error")

typedef enum
{
#define _(sym, str) VCDP_LOOKUP_ERROR_##sym,
  foreach_vcdp_handoff_error
#undef _
    VCDP_HANDOFF_N_ERROR,
} vcdp_handoff_error_t;

static char *vcdp_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_handoff_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
} vcdp_lookup_trace_t;

typedef struct
{
  u32 next_index;
  u32 flow_id;
} vcdp_handoff_trace_t;

#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32 ((__m128i) (v), x, i)

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,	[IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_TCP] = 32,	[IP_PROTOCOL_UDP] = 32,
  [IP_PROTOCOL_IPSEC_ESP] = 32, [IP_PROTOCOL_IPSEC_AH] = 32,
};

/* TODO: add ICMP, ESP, and AH (+ additional
 * branching or lookup for different
 * shuffling mask) */
static const u64 tcp_udp_bitmask =
  ((1 << IP_PROTOCOL_TCP) | (1 << IP_PROTOCOL_UDP));
static const u8x16 key_shuff_no_norm = { 0, 1, 2,  3,  -1, 5,  -1, -1,
					 8, 9, 10, 11, 12, 13, 14, 15 };
static const u8x16 key_shuff_norm = { 2,  3,  0,  1,  -1, 5, -1, -1,
				      12, 13, 14, 15, 8,  9, 10, 11 };
static const u8x16 src_ip_byteswap_x2 = { 11, 10, 9, 8, -1, -1, -1, -1,
					  11, 10, 9, 8, -1, -1, -1, -1 };
static const u8x16 dst_ip_byteswap_x2 = { 15, 14, 13, 12, -1, -1, -1, -1,
					  15, 14, 13, 12, -1, -1, -1, -1 };

static_always_inline void
calc_key (vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey,
	  u64 *lookup_val, u64 *h)
{
  u8 pr;
  i64x2 norm, zero = {};
  u8x16 k, swap;
  u32 l4_hdr;
  void *next_header;

  ip4_header_t *ip = vlib_buffer_get_current (b);

  /* load last 16 bytes of ip header into 128-bit register */
  k = *(u8x16u *) ((u8 *) ip + 4);
  pr = ip->protocol;

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  norm = (((i64x2) u8x16_shuffle (k, src_ip_byteswap_x2)) >
	  ((i64x2) u8x16_shuffle (k, dst_ip_byteswap_x2)));

  /* we only normalize tcp and tcp, for other cases we reset all bits to 0 */
  norm &= i64x2_splat ((1ULL << pr) & tcp_udp_bitmask) != zero;

  swap = key_shuff_no_norm;
  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap += (key_shuff_norm - key_shuff_no_norm) & (u8x16) norm;

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  next_header = ip4_next_header (ip);
  l4_hdr = *(u32 *) next_header & pow2_mask (l4_mask_bits[pr]);
  k = (u8x16) u32x4_insert (k, l4_hdr, 0);

  k = u8x16_shuffle (k, swap);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (pr == IP_PROTOCOL_TCP)
    vcdp_buffer (b)->tcp_flags = *(u8 *) next_header + 13;
  else
    vcdp_buffer (b)->tcp_flags = 0;

  /* store key */
  skey->ip4_key.as_u8x16 = k;
  skey->context_id = context_id;
  clib_memset (skey->zeros, 0, sizeof (skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_24_8 ((clib_bihash_kv_24_8_t *) (skey));
}

static_always_inline int
vcdp_create_session (vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd,
		     vcdp_tenant_t *tenant, u16 tenant_idx, u32 thread_index,
		     f64 time_now, vcdp_session_ip4_key_t *k, u64 *h,
		     u64 *lookup_val)
{
  clib_bihash_kv_24_8_t kv = {};
  clib_bihash_kv_8_8_t kv2;
  vcdp_session_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;
  u64 session_id;
  pool_get (ptd->sessions, session);
  session_idx = session - ptd->sessions;
  clib_memcpy_fast (&kv.key, k, 24);
  pseudo_flow_idx = (lookup_val[0] & 0x1) | (session_idx << 1);
  kv.value = vcdp_session_mk_table_value (thread_index, pseudo_flow_idx);

  if (clib_bihash_add_del_24_8 (&vcdp->table4, &kv, 2))
    {
      /* colision - remote thread created same entry */
      pool_put (ptd->sessions, session);
      return 1;
    }
  session->type = VCDP_SESSION_TYPE_IP4;
  session->session_version += 1;
  session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) |
	       ptd->session_id_template;
  ptd->session_id_ctr +=
    2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->state = VCDP_SESSION_STATE_FSOL;
  kv2.key = session_id;
  kv2.value = kv.value;
  clib_bihash_add_del_8_8 (&vcdp->session_index_by_id, &kv2, 1);
  clib_memcpy_fast (session->bitmaps, tenant->bitmaps,
		    sizeof (session->bitmaps));
  clib_memcpy_fast (&session->key[VCDP_SESSION_KEY_PRIMARY], k, sizeof (*k));
  session->pseudo_dir[VCDP_SESSION_KEY_PRIMARY] = lookup_val[0] & 0x1;
  session->proto = k->ip4_key.proto;
  session->key_flags = VCDP_SESSION_KEY_FLAG_PRI_INIT_VALID |
		       VCDP_SESSION_KEY_FLAG_PRI_RESP_VALID;

  vcdp_session_timer_start (&ptd->wheel, &session->timer, session_idx,
			    time_now,
			    tenant->timeouts[VCDP_TIMEOUT_EMBRYONIC]);

  lookup_val[0] ^= kv.value;
  /* Bidirectional counter zeroing */
  vlib_zero_combined_counter (&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0]);
  vlib_zero_combined_counter (&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0] | 0x1);
  vlib_increment_simple_counter (
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_CREATED],
    thread_index, tenant_idx, 1);
  return 0;
}

static_always_inline void
vcdp_lookup_four (clib_bihash_24_8_t *t, vlib_buffer_t **b,
		  vcdp_session_ip4_key_t *k, u64 *lookup_val, u64 *h,
		  int prefetch_buffer_stride)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[0]);
      clib_prefetch_load (pb[0]->data);
    }

  calc_key (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[1]);
      clib_prefetch_load (pb[1]->data);
    }

  calc_key (b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[2]);
      clib_prefetch_load (pb[2]->data);
    }

  calc_key (b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[3]);
      clib_prefetch_load (pb[3]->data);
    }

  calc_key (b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3);
}

VLIB_NODE_FN (vcdp_lookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  clib_bihash_kv_24_8_t kv = {};
  vcdp_tenant_t *tenant;
  vcdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  vlib_buffer_t *local_bufs[VLIB_FRAME_SIZE];
  u32 local_flow_indices[VLIB_FRAME_SIZE];
  vcdp_session_ip4_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 lengths[VLIB_FRAME_SIZE], *len = lengths;
  f64 time_now = vlib_time_now (vm);
  /* lookup_vals contains: (Phase 1) packet_dir, (Phase 2) thread_index|||
   * flow_index */
  u64 __attribute__ ((aligned (32))) lookup_vals[VLIB_FRAME_SIZE],
    *lv = lookup_vals;
  u16 hit_count = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  ptd->current_time = time_now;
  vcdp_expire_timers (&ptd->wheel, time_now);
  vcdp_session_index_iterate_expired (ptd, session_index)
    vcdp_session_remove_or_rearm (vcdp, ptd, thread_index, session_index);

  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      vcdp_lookup_four (&vcdp->table4, b, k, lv, h, 4);

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      vcdp_lookup_four (&vcdp->table4, b, k, lv, h, 0);

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      calc_key (b[0], b[0]->flow_id, k + 0, lv + 0, h + 0);

      b += 1;
      k += 1;
      lv += 1;
      h += 1;
      n_left -= 1;
    }

  n_left = frame->n_vectors;
  b = bufs;
  h = hashes;
  k = keys;
  lv = lookup_vals;
  while (n_left)
    {
      if (PREDICT_TRUE (n_left > 8))
	clib_bihash_prefetch_bucket_24_8 (&vcdp->table4, h[8]);

      if (PREDICT_TRUE (n_left > 1))
	vlib_prefetch_buffer_header (b[1], STORE);

      clib_memcpy_fast (&kv.key, k, 24);
      if (clib_bihash_search_inline_with_hash_24_8 (&vcdp->table4, h[0], &kv))
	{
	  u16 tenant_idx = vcdp_buffer (b[0])->tenant_index;
	  tenant = vcdp_tenant_at_index (vcdp, tenant_idx);
	  /* if there is colision, we just reiterate */
	  if (vcdp_create_session (vcdp, ptd, tenant, tenant_idx, thread_index,
				   time_now, k, h, lv))
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   VCDP_LOOKUP_ERROR_COLLISION, 1);
	      continue;
	    }
	}
      else
	{
	  lv[0] ^= kv.value;
	  hit_count++;
	}

      b[0]->flow_id = lv[0] & (~(u32) 0);
      len[0] = vlib_buffer_length_in_chain (vm, b[0]);
      b += 1;
      n_left -= 1;
      k += 1;
      h += 1;
      lv += 1;
      len += 1;
    }

  n_left = frame->n_vectors;
  lv = lookup_vals;
  b = bufs;
  bi = from;
  len = lengths;
  while (n_left)
    {
      u32 flow_thread_index = vcdp_thread_index_from_lookup (lv[0]);
      u32 flow_index = lv[0] & (~(u32) 0);
      vlib_combined_counter_main_t *vcm =
	&vcdp->per_thread_data[flow_thread_index]
	   .per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP];
      vlib_increment_combined_counter (vcm, thread_index, flow_index, 1,
				       len[0]);
      if (flow_thread_index == thread_index)
	{
	  /* known flow which belongs to this thread */
	  to_local[n_local] = bi[0];
	  local_flow_indices[n_local] = flow_index;
	  local_bufs[n_local] = b[0];
	  n_local++;
	}
      else
	{
	  /* known flow which belongs to remote thread */
	  to_remote[n_remote] = bi[0];
	  thread_indices[n_remote] = flow_thread_index;
	  n_remote++;
	}

      n_left -= 1;
      lv += 1;
      b += 1;
      bi += 1;
      len += 1;
    }

  /* handover buffers to remote node */
  if (n_remote)
    {
      u32 n_remote_enq;
      n_remote_enq = vlib_buffer_enqueue_to_thread (
	vm, vcdp->frame_queue_index, to_remote, thread_indices, n_remote, 1);
      vlib_node_increment_counter (vm, node->node_index,
				   VCDP_LOOKUP_ERROR_REMOTE, n_remote_enq);
      vlib_node_increment_counter (vm, node->node_index,
				   VCDP_LOOKUP_ERROR_CON_DROP,
				   n_remote - n_remote_enq);
    }

  /* enqueue local */
  if (n_local)
    {
      u16 *current_next = local_next_indices;
      u32 *local_flow_index = local_flow_indices;
      b = local_bufs;
      n_left = n_local;

      /* TODO: prefetch session and buffer + 4 loop */
      while (n_left)
	{
	  session_index = local_flow_index[0] >> 1;
	  session = vcdp_session_at_index (ptd, session_index);
	  u32 pbmp =
	    session
	      ->bitmaps[vcdp_direction_from_flow_index (local_flow_index[0])];
	  vcdp_buffer (b[0])->service_bitmap = pbmp;

	  /* The tenant of the buffer is the tenant of the session */
	  vcdp_buffer (b[0])->tenant_index = session->tenant_idx;

	  vcdp_next (b[0], current_next);

	  local_flow_index += 1;
	  current_next += 1;
	  b += 1;
	  n_left -= 1;
	}
      vlib_buffer_enqueue_to_next (vm, node, to_local, local_next_indices,
				   n_local);
      vlib_node_increment_counter (vm, node->node_index,
				   VCDP_LOOKUP_ERROR_LOCAL, n_local);
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      bi = from;
      h = hashes;
      u32 *in_local = to_local;
      u32 *in_remote = to_remote;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_lookup_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->flow_id = b[0]->flow_id;
	      t->hash = h[0];
	      if (bi[0] == in_local[0])
		{
		  t->next_index = local_next_indices[(in_local++) - to_local];
		}
	      else
		{
		  t->next_index = ~0;
		  in_remote++;
		}
	      bi++;
	      b++;
	      h++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (vcdp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 time_now = vlib_time_now (vm);

  ptd->current_time = time_now;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  /*TODO: prefetch, quad or octo loop...*/
  while (n_left)
    {
      u32 flow_index = b[0]->flow_id;
      u32 session_index = flow_index >> 1;
      vcdp_session_t *session = vcdp_session_at_index (ptd, session_index);
      u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index (flow_index)];
      vcdp_buffer (b[0])->service_bitmap = pbmp;
      vcdp_next (b[0], current_next);

      current_next += 1;
      b += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      current_next = next_indices;
      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->next_index = current_next[0];
	      b++;
	      current_next++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

static u8 *
format_vcdp_lookup_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_lookup_trace_t *t = va_arg (*args, vcdp_lookup_trace_t *);

  s = format (s,
	      "vcdp-lookup: sw_if_index %d, next index %d hash 0x%x "
	      "flow-id %u (session %u, %s)",
	      t->sw_if_index, t->next_index, t->hash, t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

static u8 *
format_vcdp_handoff_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_handoff_trace_t *t = va_arg (*args, vcdp_handoff_trace_t *);

  s = format (s,
	      "vcdp-handoff: next index %d "
	      "flow-id %u (session %u, %s)",
	      t->next_index, t->flow_id, t->flow_id >> 1,
	      t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vcdp_lookup_node) =
{
  .name = "vcdp-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_lookup_error_strings),
  .error_strings = vcdp_lookup_error_strings,

  .n_next_nodes = VCDP_SERVICE_N,

  /* edit / add dispositions here */
  .next_nodes = {
#define _(s, n, x) [VCDP_SERVICE_##s] = n,
      foreach_vcdp_service
#undef _
  },
};

VLIB_REGISTER_NODE (vcdp_handoff_node) = {
  .name = "vcdp-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_handoff_error_strings),
  .error_strings = vcdp_handoff_error_strings,

  .sibling_of = "vcdp-lookup",

};
