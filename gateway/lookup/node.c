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
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <gateway/gateway.h>

/* packet trace format function */

#define foreach_gw_lookup_next _ (GW_COUNTER, "fh-counter")

#define foreach_gw_lookup_error                                               \
  _ (MISS, "flow miss")                                                       \
  _ (LOCAL, "local flow")                                                     \
  _ (REMOTE, "remote flow")                                                   \
  _ (COLLISION, "hash add collision")                                         \
  _ (CON_DROP, "handoff drop")

typedef enum
{
#define _(sym, str) GW_LOOKUP_ERROR_##sym,
  foreach_gw_lookup_error
#undef _
    GW_LOOKUP_N_ERROR,
} gw_lookup_error_t;

static char *gw_lookup_error_strings[] = {
#define _(sym, string) string,
  foreach_gw_lookup_error
#undef _
};

typedef enum
{
#define _(s, n) GW_LOOKUP_NEXT_##s,
  foreach_gw_lookup_next
#undef _
    GW_LOOKUP_N_NEXT,
} gw_lookup_next_t;

#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32 ((__m128i) (v), x, i)

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,	[IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_TCP] = 32,	[IP_PROTOCOL_UDP] = 32,
  [IP_PROTOCOL_IPSEC_ESP] = 32, [IP_PROTOCOL_IPSEC_AH] = 32,
};

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
gw_calc_key (vlib_buffer_t *b, int off, gw_ip4_key_t *key, u32 *f, u64 *h)
{
  u8 pr;
  i64x2 norm, zero = {};
  u8x16 k, swap;
  u32 l4_hdr;
  void *next_header;

  ip4_header_t *ip = vlib_buffer_get_current (b) + off;

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
  f[0] = ((u32x4) norm)[0];

  /* extract tcp flags */
  if (pr == IP_PROTOCOL_TCP)
    vnet_buffer (b)->dont_waste_me = *(u8 *) next_header + 13;
  else
    vnet_buffer (b)->dont_waste_me = 0;

  /* store key */
  key->as_u8x16 = k;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8 ((clib_bihash_kv_16_8_t *) (key));
}

static_always_inline int
gw_add_flow (gw_main_t *fm, gw_per_thread_data_t *ptd, u32 thread_index,
	     u32 first_flow_index, gw_ip4_key_t *k, u64 *h, u32 *fid)
{
  clib_bihash_kv_16_8_t kv = {};
  gw_flow_t *f;

  pool_get_zero (ptd->flows, f);
  clib_memcpy_fast (&kv.key, k, 16);
  kv.value = gw_flow_id (GW_FLOW_TYPE_IP4, thread_index, f - ptd->flows, 0);

  if (clib_bihash_add_del_16_8 (&fm->table4, &kv, 2))
    {
      /* colision - remote thread created same entry */
      pool_put (ptd->flows, f);
      return 1;
    }

  f->ip_addr_hi = k->ip_addr_hi;
  f->ip_addr_lo = k->ip_addr_lo;
  f->port_hi = k->port_hi;
  f->port_lo = k->port_lo;
  f->proto = k->proto;
  fid[0] |= kv.value;
  return 0;
}

static_always_inline void
gw_lookup_four (clib_bihash_16_8_t *t, vlib_buffer_t **b, gw_ip4_key_t *k,
		u32 *f, u64 *h, int prefetch_buffer_stride)
{
  u8 off = sizeof (ethernet_header_t);
  vlib_buffer_t **pb = b + prefetch_buffer_stride;

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[0]);
      clib_prefetch_load (pb[0]->data);
    }

  gw_calc_key (b[0], off, k + 0, f + 0, h + 0);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[1]);
      clib_prefetch_load (pb[1]->data);
    }

  gw_calc_key (b[1], off, k + 1, f + 1, h + 1);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[2]);
      clib_prefetch_load (pb[2]->data);
    }

  gw_calc_key (b[2], off, k + 2, f + 2, h + 2);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[3]);
      clib_prefetch_load (pb[3]->data);
    }

  gw_calc_key (b[3], off, k + 3, f + 3, h + 3);
}

VLIB_NODE_FN (gw_lookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  gw_main_t *fm = &gateway_main;
  u32 thread_index = vm->thread_index;
  u32 first_flow_index = thread_index << GW_LOG2_FLOWS_PER_THREAD;
  gw_per_thread_data_t *ptd =
    vec_elt_at_index (fm->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  clib_bihash_kv_16_8_t kv = {};
  u32 *bi, *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  gw_ip4_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 __attribute__ ((aligned (32))) flow_ids[VLIB_FRAME_SIZE], *f = flow_ids;
  u16 hit_count = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;

  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      gw_lookup_four (&fm->table4, b, k, f, h, 4);

      b += 4;
      k += 4;
      h += 4;
      f += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      gw_lookup_four (&fm->table4, b, k, f, h, 0);

      b += 4;
      k += 4;
      h += 4;
      f += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      u8 off = sizeof (ethernet_header_t);
      gw_calc_key (b[0], off, k + 0, f + 0, h + 0);

      b += 1;
      k += 1;
      h += 1;
      f += 1;
      n_left -= 1;
    }

#ifdef CLIB_HAVE_VEC256
  for (int i = 0; i < frame->n_vectors; i += 8)
    *(u32x8 *) (flow_ids + i) &= u32x8_splat (GW_FLOW_ID_DIRECTION_MASK);
#else
  for (int i = 0; i < frame->n_vectors; i++)
    flow_ids[i] &= GW_FLOW_ID_DIRECTION_MASK;
#endif

  n_left = frame->n_vectors;
  h = hashes;
  k = keys;
  f = flow_ids;

  while (n_left)
    {
      if (PREDICT_TRUE (n_left > 8))
	clib_bihash_prefetch_bucket_16_8 (&fm->table4, h[8]);

      clib_memcpy_fast (&kv.key, k, 16);
      if (clib_bihash_search_inline_with_hash_16_8 (&fm->table4, h[0], &kv))
	{
	  /* if there is colision, we just reiterate */
	  if (gw_add_flow (fm, ptd, thread_index, first_flow_index, k, h, f))
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   GW_LOOKUP_ERROR_COLLISION, 1);
	      continue;
	    }
	}
      else
	{
	  f[0] |= kv.value;
	  hit_count++;
	}

      n_left -= 1;
      k += 1;
      h += 1;
      f += 1;
    }

  n_left = frame->n_vectors;
  f = flow_ids;
  b = bufs;
  bi = from;

  while (n_left)
    {
      u32 flow_thread_index = gw_thread_index_from_flow_id (f[0]);
      b[0]->flow_id = f[0];
      if (flow_thread_index == thread_index)
	{
	  /* known flow which belongs to this thread */
	  to_local[n_local] = bi[0];
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
      f += 1;
      b += 1;
      bi += 1;
    }

  /* handover buffers to remote node */
  if (n_remote)
    {
      u32 n_remote_enq;
      n_remote_enq = vlib_buffer_enqueue_to_thread (
	vm, fm->frame_queue_index, to_remote, thread_indices, n_remote, 1);
      vlib_node_increment_counter (vm, node->node_index,
				   GW_LOOKUP_ERROR_REMOTE, n_remote_enq);
      vlib_node_increment_counter (vm, node->node_index,
				   GW_LOOKUP_ERROR_CON_DROP,
				   n_remote - n_remote_enq);
    }

  /* enqueue local */
  if (n_local)
    {
      vlib_buffer_enqueue_to_single_next (vm, node, to_local,
					  GW_LOOKUP_NEXT_GW_COUNTER, n_local);
      vlib_node_increment_counter (vm, node->node_index, GW_LOOKUP_ERROR_LOCAL,
				   n_local);
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      h = hashes;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      gw_lookup_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->flow_id = b[0]->flow_id;
	      t->next_index = GW_LOOKUP_NEXT_GW_COUNTER;
	      t->hash = h[0];
	      b++;
	      h++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gw_lookup_node) =
{
  .name = "vcdp-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_gw_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gw_lookup_error_strings),
  .error_strings = gw_lookup_error_strings,

  .n_next_nodes = GW_LOOKUP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
#define _(s, n) [GW_LOOKUP_NEXT_##s] = n,
      foreach_gw_lookup_next
#undef _
  },
};
