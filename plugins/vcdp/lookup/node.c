// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "lookup_inlines.h"

#define foreach_vcdp_lookup_error                                                                                      \
  _(MISS, "flow miss")                                                                                                 \
  _(LOCAL, "local flow")                                                                                               \
  _(REMOTE, "remote flow")                                                                                             \
  _(COLLISION, "hash add collision")                                                                                   \
  _(CON_DROP, "handoff drop")

typedef enum {
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

#define foreach_vcdp_handoff_error _(NOERROR, "no error")

typedef enum {
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

typedef struct {
  u32 sw_if_index;
  union {
    vcdp_session_ip4_key_t k4;
    vcdp_session_ip6_key_t k6;
  };
  u8 is_ip6;
  u8 is_sp;
  union {
    struct {
      u32 next_index;
      u64 hash;
      u32 flow_id;
    };
    struct {
      u32 sp_index;
      u32 sp_node_index;
    };
  };
} vcdp_lookup_trace_t;

typedef struct {
  u32 next_index;
  u32 flow_id;
} vcdp_handoff_trace_t;

static_always_inline int
vcdp_create_session_v4(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val, u32 rx_id)
{
  return vcdp_create_session_inline(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k, h, lookup_val, 0, rx_id);
}

static_always_inline int
vcdp_create_session_v6(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val)
{
  return vcdp_create_session_inline(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k, h, lookup_val, 1,
                                    0 /* NO v6 */);
}

static_always_inline u8
vcdp_lookup_four_v4(vlib_buffer_t **b, vcdp_session_ip4_key_t *k, u64 *lookup_val, u64 *h, i16 *l4_hdr_offset,
                    int prefetch_buffer_stride, u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[0]);
    clib_prefetch_load(pb[0]->data);
  }

  slowpath_needed |= vcdp_calc_key_v4(b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0, l4_hdr_offset + 0, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[1]);
    clib_prefetch_load(pb[1]->data);
  }

  slowpath_needed |= vcdp_calc_key_v4(b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1, l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[2]);
    clib_prefetch_load(pb[2]->data);
  }

  slowpath_needed |= vcdp_calc_key_v4(b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2, l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[3]);
    clib_prefetch_load(pb[3]->data);
  }

  slowpath_needed |= vcdp_calc_key_v4(b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3, l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline u8
vcdp_lookup_four_v6(vlib_buffer_t **b, vcdp_session_ip6_key_t *k, u64 *lookup_val, u64 *h, i16 *l4_hdr_offset,
                    int prefetch_buffer_stride, u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[0]);
    clib_prefetch_load(pb[0]->data);
  }

  slowpath_needed |= vcdp_calc_key_v6(b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0, l4_hdr_offset + 0, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[1]);
    clib_prefetch_load(pb[1]->data);
  }

  slowpath_needed |= vcdp_calc_key_v6(b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1, l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[2]);
    clib_prefetch_load(pb[2]->data);
  }

  slowpath_needed |= vcdp_calc_key_v6(b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2, l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[3]);
    clib_prefetch_load(pb[3]->data);
  }

  slowpath_needed |= vcdp_calc_key_v6(b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3, l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline void
vcdp_prepare_all_keys_v4_slow(vlib_buffer_t **b, vcdp_session_ip4_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left);

static_always_inline void
vcdp_prepare_all_keys_v6_slow(vlib_buffer_t **b, vcdp_session_ip6_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left);

static_always_inline uword
vcdp_prepare_all_keys_v4(vlib_buffer_t **b, vcdp_session_ip4_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
                         u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8) {
    if (vcdp_lookup_four_v4(b, k, lv, h, l4_hdr_offset, 4, slowpath) && !slowpath)
      return n_left;

    b += 4;
    k += 4;
    lv += 4;
    h += 4;
    l4_hdr_offset += 4;
    n_left -= 4;
  }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4) {
    if (vcdp_lookup_four_v4(b, k, lv, h, l4_hdr_offset, 0, slowpath) && !slowpath)
      return n_left;

    b += 4;
    k += 4;
    lv += 4;
    h += 4;
    l4_hdr_offset += 4;
    n_left -= 4;
  }

  while (n_left > 0) {
    if (vcdp_calc_key_v4(b[0], b[0]->flow_id, k + 0, lv + 0, h + 0, l4_hdr_offset + 0, slowpath) && !slowpath)
      return n_left;

    b += 1;
    k += 1;
    lv += 1;
    h += 1;
    l4_hdr_offset += 1;
    n_left -= 1;
  }
  return 0;
}

static_always_inline uword
vcdp_prepare_all_keys_v6(vlib_buffer_t **b, vcdp_session_ip6_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
                         u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8) {
    if (vcdp_lookup_four_v6(b, k, lv, h, l4_hdr_offset, 4, slowpath) && !slowpath)
      return n_left;

    b += 4;
    k += 4;
    lv += 4;
    h += 4;
    l4_hdr_offset += 4;
    n_left -= 4;
  }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4) {
    if (vcdp_lookup_four_v6(b, k, lv, h, l4_hdr_offset, 0, slowpath) && !slowpath)
      return n_left;

    b += 4;
    k += 4;
    lv += 4;
    h += 4;
    l4_hdr_offset += 4;
    n_left -= 4;
  }

  while (n_left > 0) {
    if (vcdp_calc_key_v6(b[0], b[0]->flow_id, k + 0, lv + 0, h + 0, l4_hdr_offset, slowpath) && !slowpath)
      return n_left;

    b += 1;
    k += 1;
    lv += 1;
    h += 1;
    l4_hdr_offset += 1;
    n_left -= 1;
  }
  return 0;
}

static_always_inline void
vcdp_prepare_all_keys_v4_slow(vlib_buffer_t **b, vcdp_session_ip4_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left)
{
  vcdp_prepare_all_keys_v4(b, k, lv, h, l4_hdr_offset, n_left, 1);
}
static_always_inline uword
vcdp_prepare_all_keys_v4_fast(vlib_buffer_t **b, vcdp_session_ip4_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left)
{
  return vcdp_prepare_all_keys_v4(b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline void
vcdp_prepare_all_keys_v6_slow(vlib_buffer_t **b, vcdp_session_ip6_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left)
{
  vcdp_prepare_all_keys_v6(b, k, lv, h, l4_hdr_offset, n_left, 1);
}

static_always_inline uword
vcdp_prepare_all_keys_v6_fast(vlib_buffer_t **b, vcdp_session_ip6_key_t *k, u64 *lv, u64 *h, i16 *l4_hdr_offset,
                              u32 n_left)
{
  return vcdp_prepare_all_keys_v6(b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline uword
vcdp_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_ipv6)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vcdp_bihash_kv46_t kv = {};
  vcdp_tenant_t *tenant;
  vcdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u32 to_sp[VLIB_FRAME_SIZE], n_to_sp = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  u32 sp_indices[VLIB_FRAME_SIZE];
  u32 sp_node_indices[VLIB_FRAME_SIZE];
  vlib_buffer_t *local_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *to_sp_bufs[VLIB_FRAME_SIZE];
  u32 local_flow_indices[VLIB_FRAME_SIZE];
  VCDP_SESSION_IP46_KEYS_TYPE(VLIB_FRAME_SIZE) keys;

  vcdp_session_ip4_key_t *k4 = keys.keys4;
  vcdp_session_ip6_key_t *k6 = keys.keys6;

  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 lengths[VLIB_FRAME_SIZE], *len = lengths;
  i16 l4_hdr_off[VLIB_FRAME_SIZE], *l4o = l4_hdr_off;
  f64 time_now = vlib_time_now(vm);
  /* lookup_vals contains:
   * - (Phase 1) to_slow_path_node (1bit)
                  ||| slow_path_node_index (31bits)
   *              ||| zeros(31bits)
   *              |||
   *              ||| packet_dir (1bit)
   *
   * - (Phase 2) thread_index (32bits)||| flow_index (32bits)
      OR same as Phase 1 if slow path
      ASSUMPTION: thread index < 2^31 */
  u64 __attribute__((aligned(32))) lookup_vals[VLIB_FRAME_SIZE], *lv = lookup_vals;
  u16 hit_count = 0;
  uword n_left_slow_keys;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  ptd->current_time = time_now;
  vcdp_expire_timers(&ptd->wheel, time_now);
  vcdp_session_index_iterate_expired(ptd, session_index)
    vcdp_session_remove_or_rearm(vcdp, ptd, thread_index, session_index);

  if (is_ipv6) {
    if (PREDICT_FALSE((n_left_slow_keys = vcdp_prepare_all_keys_v6_fast(b, k6, lv, h, l4o, n_left)))) {
      uword n_done = n_left - n_left_slow_keys;
      vcdp_prepare_all_keys_v6_slow(b + n_done, k6 + n_done, lv + n_done, h + n_done, l4o + n_done, n_left_slow_keys);
    }
  } else {
    if (PREDICT_FALSE((n_left_slow_keys = vcdp_prepare_all_keys_v4_fast(b, k4, lv, h, l4o, n_left)))) {
      uword n_done = n_left - n_left_slow_keys;
      vcdp_prepare_all_keys_v4_slow(b + n_done, k4 + n_done, lv + n_done, h + n_done, l4o + n_done, n_left_slow_keys);
    }
  }

  if (is_ipv6)
    while (n_left) {
      if (PREDICT_TRUE(n_left > 8))
        clib_bihash_prefetch_bucket_48_8(&vcdp->table6, h[8]);

      if (PREDICT_TRUE(n_left > 1))
        vlib_prefetch_buffer_header(b[1], STORE);

      if (PREDICT_FALSE(lv[0] & VCDP_LV_TO_SP))
        goto next_pkt6;

      clib_memcpy_fast(&kv.kv6.key, k6, 48);
      if (clib_bihash_search_inline_with_hash_48_8(&vcdp->table6, h[0], &kv.kv6)) {
        u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
        tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
        /* if there is collision, we just reiterate */
        if (vcdp_create_session_v6(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k6, h, lv)) {
          vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_COLLISION, 1);
          continue;
        }
      } else {
        lv[0] ^= kv.kv6.value;
        hit_count++;
      }

      b[0]->flow_id = lv[0] & (~(u32) 0);

    next_pkt6:
      b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      vnet_buffer(b[0])->l4_hdr_offset = l4o[0];
      len[0] = vlib_buffer_length_in_chain(vm, b[0]);

      b += 1;
      n_left -= 1;
      k6 += 1;
      h += 1;
      lv += 1;
      len += 1;
    }
  else
    while (n_left) {
      if (PREDICT_TRUE(n_left > 8))
        clib_bihash_prefetch_bucket_24_8(&vcdp->table4, h[8]);

      if (PREDICT_TRUE(n_left > 1))
        vlib_prefetch_buffer_header(b[1], STORE);

      if (PREDICT_FALSE(lv[0] & VCDP_LV_TO_SP))
        goto next_pkt4;

      clib_memcpy_fast(&kv.kv4.key, k4, 24);
      if (clib_bihash_search_inline_with_hash_24_8(&vcdp->table4, h[0], &kv.kv4)) {
        u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
        tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
        /* if there is collision, we just reiterate */
        if (tenant->flags & VCDP_TENANT_FLAG_NO_CREATE) {
          clib_warning("OLE: Trying to create session from outside");
          goto next_pkt4;
        }
        if (vcdp_create_session_v4(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k4, h, lv,
                                   vcdp_buffer(b[0])->rx_id)) {
          vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_COLLISION, 1);
          continue;
        }
      } else {
        lv[0] ^= kv.kv4.value;
        hit_count++;
      }

      b[0]->flow_id = lv[0] & (~(u32) 0);

    next_pkt4:
      b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      vnet_buffer(b[0])->l4_hdr_offset = l4o[0];
      len[0] = vlib_buffer_length_in_chain(vm, b[0]);

      b += 1;
      n_left -= 1;
      k4 += 1;
      h += 1;
      lv += 1;
      len += 1;
      l4o += 1;
    }

  n_left = frame->n_vectors;
  lv = lookup_vals;
  b = bufs;
  bi = from;
  len = lengths;
  while (n_left) {
    u32 flow_thread_index;
    u32 flow_index;
    vlib_combined_counter_main_t *vcm;

    if (lv[0] & VCDP_LV_TO_SP) {
      to_sp[n_to_sp] = bi[0];
      sp_indices[n_to_sp] = (lv[0] & ~(VCDP_LV_TO_SP)) >> 32;
      to_sp_bufs[n_to_sp] = b[0];
      n_to_sp++;
      goto next_packet2;
    }

    flow_thread_index = vcdp_thread_index_from_lookup(lv[0]);
    flow_index = lv[0] & (~(u32) 0);
    vcm = &vcdp->per_thread_data[flow_thread_index].per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP];
    vlib_increment_combined_counter(vcm, thread_index, flow_index, 1, len[0]);
    if (flow_thread_index == thread_index) {
      /* known flow which belongs to this thread */
      to_local[n_local] = bi[0];
      local_flow_indices[n_local] = flow_index;
      local_bufs[n_local] = b[0];
      n_local++;
    } else {
      /* known flow which belongs to remote thread */
      to_remote[n_remote] = bi[0];
      thread_indices[n_remote] = flow_thread_index;
      n_remote++;
    }
  next_packet2:
    n_left -= 1;
    lv += 1;
    b += 1;
    bi += 1;
    len += 1;
  }

  /* handover buffers to remote node */
  if (n_remote) {
    u32 n_remote_enq;
    n_remote_enq =
      vlib_buffer_enqueue_to_thread(vm, node, vcdp->frame_queue_index, to_remote, thread_indices, n_remote, 1);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_REMOTE, n_remote_enq);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_CON_DROP, n_remote - n_remote_enq);
  }

  /* enqueue local */
  if (n_local) {
    u16 *current_next = local_next_indices;
    u32 *local_flow_index = local_flow_indices;
    b = local_bufs;
    n_left = n_local;

    /* TODO: prefetch session and buffer + 4 loop */
    while (n_left) {
      session_index = local_flow_index[0] >> 1;
      session = vcdp_session_at_index(ptd, session_index);
      u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index(local_flow_index[0])];
      vcdp_buffer(b[0])->service_bitmap = pbmp;

      /* The tenant of the buffer is the tenant of the session */
      vcdp_buffer(b[0])->tenant_index = session->tenant_idx;

      vcdp_next(b[0], current_next);

      local_flow_index += 1;
      current_next += 1;
      b += 1;
      n_left -= 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, to_local, local_next_indices, n_local);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_LOCAL, n_local);
  }

  if (n_to_sp) {
    vlib_frame_t *f = NULL;
    u32 *current_next_slot = NULL;
    u32 current_left_to_next = 0;
    u32 *current_to_sp = to_sp;
    u32 *sp_index = sp_indices;
    u32 *sp_node_index = sp_node_indices;
    u32 last_node_index = VLIB_INVALID_NODE_INDEX;

    b = to_sp_bufs;
    n_left = n_to_sp;

    while (n_left) {
      u32 node_index;
      u16 tenant_idx;
      vcdp_tenant_t *tenant;

      tenant_idx = vcdp_buffer(b[0])->tenant_index;
      tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
      node_index = tenant->sp_node_indices[sp_index[0]];
      sp_node_index[0] = node_index;

      if (PREDICT_FALSE(node_index != last_node_index) || current_left_to_next == 0) {
        if (f != NULL)
          vlib_put_frame_to_node(vm, last_node_index, f);
        f = vlib_get_frame_to_node(vm, node_index);
        f->frame_flags |= node->flags & VLIB_NODE_FLAG_TRACE;
        current_next_slot = vlib_frame_vector_args(f);
        current_left_to_next = VLIB_FRAME_SIZE;
        last_node_index = node_index;
      }

      current_next_slot[0] = current_to_sp[0];

      f->n_vectors += 1;
      current_to_sp += 1;
      b += 1;
      sp_index += 1;
      sp_node_index += 1;
      current_next_slot += 1;

      current_left_to_next -= 1;
      n_left -= 1;
    }
    vlib_put_frame_to_node(vm, last_node_index, f);
  }

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    bi = from;
    h = hashes;
    u32 *in_local = to_local;
    u32 *in_remote = to_remote;
    u32 *in_sp = to_sp;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_lookup_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
        t->flow_id = b[0]->flow_id;
        t->hash = h[0];
        t->is_sp = 0;
        if (bi[0] == in_local[0]) {
          t->next_index = local_next_indices[(in_local++) - to_local];
        } else if (bi[0] == in_remote[0]) {
          t->next_index = ~0;
          in_remote++;
        } else {
          t->is_sp = 1;
          t->sp_index = sp_indices[in_sp - to_sp];
          t->sp_node_index = sp_node_indices[in_sp - to_sp];
          in_sp++;
        }

        if ((t->is_ip6 = is_ipv6))
          clib_memcpy(&t->k6, &keys.keys6[i], sizeof(t->k6));
        else
          clib_memcpy(&t->k4, &keys.keys4[i], sizeof(t->k4));

        bi++;
        b++;
        h++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_lookup_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return vcdp_lookup_inline(vm, node, frame, 0); }

VLIB_NODE_FN(vcdp_lookup_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return vcdp_lookup_inline(vm, node, frame, 1); }

VLIB_NODE_FN(vcdp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 time_now = vlib_time_now(vm);

  ptd->current_time = time_now;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  /*TODO: prefetch, quad or octo loop...*/
  while (n_left) {
    u32 flow_index = b[0]->flow_id;
    u32 session_index = flow_index >> 1;
    vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);
    u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index(flow_index)];
    vcdp_buffer(b[0])->service_bitmap = pbmp;
    vcdp_next(b[0], current_next);

    current_next += 1;
    b += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    current_next = next_indices;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_handoff_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->next_index = current_next[0];
        b++;
        current_next++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

static u8 *
format_vcdp_lookup_trace(u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_lookup_trace_t *t = va_arg(*args, vcdp_lookup_trace_t *);

  if (!t->is_sp)
    s = format(s,
               "vcdp-lookup: sw_if_index %d, next index %d hash 0x%x "
               "flow-id %u (session %u, %s) key 0x%U",
               t->sw_if_index, t->next_index, t->hash, t->flow_id, t->flow_id >> 1,
               t->flow_id & 0x1 ? "reverse" : "forward", format_hex_bytes_no_wrap,
               t->is_ip6 ? (u8 *) &t->k6 : (u8 *) &t->k4, t->is_ip6 ? sizeof(t->k6) : sizeof(t->k4));
  else
    s = format(s,
               "vcdp-lookup: sw_if_index %d, slow-path (%U) "
               "slow-path node index %d key 0x%U",
               t->sw_if_index, format_vcdp_sp_node, t->sp_index, format_vlib_node_name, vm, t->sp_node_index,
               format_hex_bytes_no_wrap, t->is_ip6 ? (u8 *) &t->k6 : (u8 *) &t->k4,
               t->is_ip6 ? sizeof(t->k6) : sizeof(t->k4));
  return s;
}

static u8 *
format_vcdp_handoff_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_handoff_trace_t *t = va_arg(*args, vcdp_handoff_trace_t *);

  s = format(s,
             "vcdp-handoff: next index %d "
             "flow-id %u (session %u, %s)",
             t->next_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(vcdp_lookup_ip4_node) = {
  .name = "vcdp-lookup-ip4",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_lookup_error_strings),
  .error_strings = vcdp_lookup_error_strings,
};

VLIB_REGISTER_NODE(vcdp_lookup_ip6_node) = {
  .name = "vcdp-lookup-ip6",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_lookup_error_strings),
  .error_strings = vcdp_lookup_error_strings,
};

VLIB_REGISTER_NODE(vcdp_handoff_node) = {
  .name = "vcdp-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_handoff_error_strings),
  .error_strings = vcdp_handoff_error_strings,

  .sibling_of = "vcdp-lookup-ip4",

};
