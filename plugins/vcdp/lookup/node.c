// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "lookup_inlines.h"

#define foreach_vcdp_lookup_error                                                                                      \
  _(MISS, miss, ERROR, "flow miss")                                                                                    \
  _(REMOTE, remote, INFO, "remote flow")                                                                               \
  _(COLLISION, collision, ERROR, "hash add collision")                                                                 \
  _(CON_DROP, con_drop, INFO, "handoff drop")                                                                          \
  _(NO_CREATE_SESSION, no_create_session, INFO, "session not created by policy")                                       \
  _(FULL_TABLE, full_table, ERROR, "session table is full")                                                            \
  _(NO_KEY, no_key, ERROR, "not able to create 6-tuple key")

typedef enum
{
#define _(f, n, s, d) VCDP_LOOKUP_ERROR_##f,
  foreach_vcdp_lookup_error
#undef _
    VCDP_LOOKUP_N_ERROR,
} vcdp_lookup_error_t;

static vlib_error_desc_t vcdp_lookup_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_vcdp_lookup_error
#undef _
};

#define foreach_vcdp_handoff_error _(NOERROR, noerror, INFO, "no error")
typedef enum
{
#define _(f, n, s, d) VCDP_LOOKUP_ERROR_##f,
  foreach_vcdp_handoff_error
#undef _
    VCDP_HANDOFF_N_ERROR,
} vcdp_handoff_error_t;

static vlib_error_desc_t vcdp_handoff_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_vcdp_handoff_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
  u32 error;
<<<<<<< HEAD
=======
  u32 remote_worker;
>>>>>>> d70ed07 (fix lookup trace to include error or handoff)
  vcdp_session_ip4_key_t k4;
} vcdp_lookup_trace_t;

typedef struct {
  u32 next_index;
  u32 flow_id;
} vcdp_handoff_trace_t;

VCDP_SERVICE_DECLARE(tcp_check_lite)
VCDP_SERVICE_DECLARE(vcdp_tcp_mss)
VCDP_SERVICE_DECLARE(l4_lifecycle)

static void
vcdp_set_service_chain(vcdp_tenant_t *tenant, vcdp_service_chain_selector_t sc, u32 *bitmaps)
{
  clib_memcpy_fast(bitmaps, tenant->bitmaps, sizeof(tenant->bitmaps));

  switch (sc) {
  case VCDP_SERVICE_CHAIN_DEFAULT:
    /* Disable all TCP services for non-TCP traffic */
    bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(vcdp_tcp_mss);
    bitmaps[VCDP_FLOW_REVERSE] &= ~VCDP_SERVICE_MASK(vcdp_tcp_mss);
    break;
  case VCDP_SERVICE_CHAIN_TCP:
    bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(l4_lifecycle);
    bitmaps[VCDP_FLOW_REVERSE] &= ~VCDP_SERVICE_MASK(l4_lifecycle);
    bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(tcp_check_lite);
    bitmaps[VCDP_FLOW_REVERSE] |= VCDP_SERVICE_MASK(tcp_check_lite);
    break;
  case VCDP_SERVICE_CHAIN_ICMP_ERROR:
    clib_warning("ICMP ERROR SERVICE CHAIN");
    break;
  case VCDP_SERVICE_CHAIN_DROP:
    clib_warning("Drop ERROR SERVICE CHAIN");
  default:
    ASSERT(0);
  }
}

/*
 * Create a new VCDP session on the main thread
 */
VCDP_SERVICE_DECLARE(bypass)

int
vcdp_create_session_v4_2(u32 tenant_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport)
{
  // Create a new VCDP session
  clib_bihash_kv_16_8_t kv = {};
  clib_bihash_kv_8_8_t kv2;

  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);

  ASSERT(thread_index == 0); // ??
  u16 tenant_idx;
  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant) return -1;
  u32 context_id = tenant->context_id;

  vcdp_session_ip4_key_t k = {
    .context_id = context_id,
    .src = src->ip.ip4.as_u32,
    .dst = dst->ip.ip4.as_u32,
    .sport = sport,
    .dport = dport,
    .proto = protocol,
  };

  vcdp_session_t *session;
  pool_get(ptd->sessions, session);
  u32 session_idx = session - ptd->sessions;
  u32 pseudo_flow_idx = (session_idx << 1);
  u64 value = vcdp_session_mk_table_value(thread_index, pseudo_flow_idx);
  kv.key[0] = k.as_u64[0];
  kv.key[1] = k.as_u64[1];
  kv.value = value;

  if (clib_bihash_add_del_16_8(&vcdp->table4, &kv, 2)) {
    /* already exists */
    clib_warning("session already exists");
    pool_put(ptd->sessions, session);
    return 1;
  }
  session->type = VCDP_SESSION_TYPE_IP4;
  session->key_flags = VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;

  session->session_version += 1;
  u64 session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->state = VCDP_SESSION_STATE_STATIC;
  session->rx_id = ~0;
  kv2.key = session_id;
  kv2.value = value;
  clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1);

  /* Assign service chain */
  vcdp_set_service_chain(tenant, VCDP_SERVICE_CHAIN_DEFAULT, session->bitmaps);

  clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY], &k, sizeof(session->keys[0]));
  session->proto = protocol;

  return 0;
}

int
vcdp_create_session_v4(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, vcdp_session_ip4_key_t *k, u32 rx_id, u64 *lookup_val, vcdp_service_chain_selector_t sc)
{
  clib_bihash_kv_16_8_t kv = {};
  clib_bihash_kv_8_8_t kv2;
  u64 value;
  u8 proto;
  vcdp_session_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;
  u64 session_id;

  // Session table is full
  if (pool_elts(ptd->sessions) >= vcdp_cfg_main.no_sessions_per_thread) {
    return 1;
  }
  if (tenant->flags & VCDP_TENANT_FLAG_NO_CREATE)
    return 2;

  pool_get(ptd->sessions, session);
  session_idx = session - ptd->sessions;
  pseudo_flow_idx = (session_idx << 1);
  value = vcdp_session_mk_table_value(thread_index, pseudo_flow_idx);
  kv.key[0] = k->as_u64[0];
  kv.key[1] = k->as_u64[1];
  kv.value = value;
  proto = k->proto;

  if (clib_bihash_add_del_16_8(&vcdp->table4, &kv, 2)) {
    /* collision - previous packet created same entry */
    clib_warning("session already exists collision");
    pool_put(ptd->sessions, session);
    return 3;
  }
  lookup_val[0] = kv.value;
  session->type = VCDP_SESSION_TYPE_IP4;
  session->key_flags = VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;

  session->session_version += 1;
  session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->state = VCDP_SESSION_STATE_FSOL;
  session->rx_id = rx_id;
  kv2.key = session_id;
  kv2.value = value;
  clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1);

  /* Assign service chain based on traffic type */
  vcdp_set_service_chain(tenant, sc, session->bitmaps);
  // clib_memcpy_fast(session->bitmaps, tenant->bitmaps, sizeof(session->bitmaps));

  clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY], k, sizeof(session->keys[0]));
  session->proto = proto;

  vcdp_session_timer_start(&ptd->wheel, &session->timer, session_idx, time_now,
                           tenant->timeouts[VCDP_TIMEOUT_EMBRYONIC]);

  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], thread_index,
                                tenant_idx, 1);
  return 0;
}

VCDP_SERVICE_DECLARE(drop)
VCDP_SERVICE_DECLARE(nat_icmp_error)
VCDP_SERVICE_DECLARE(nat_early_rewrite)

static_always_inline uword
vcdp_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool no_create)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vcdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  vcdp_session_ip4_key_t keys[VLIB_FRAME_SIZE], *k4= keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  f64 time_now = vlib_time_now(vm);
  u64 __attribute__((aligned(32))) lookup_vals[VLIB_FRAME_SIZE], *lv = lookup_vals;
  int service_chain[VLIB_FRAME_SIZE], *sc = service_chain;
  u16 hit_count = 0;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  ptd->current_time = time_now;
  vcdp_expire_timers(&ptd->wheel, time_now);

  // Calculate key and hash
  while (n_left) {
    vcdp_calc_key_v4(b[0], b[0]->flow_id, k4, h, sc);

    h += 1;
    k4 += 1;
    b += 1;
    sc += 1;
    n_left -= 1;
  }

  h = hashes;
  k4 = keys;
  b = bufs;
  u16 *current_next = local_next_indices;
  bi = from;
  n_left = frame->n_vectors;
  lv = lookup_vals;
  sc = service_chain;

  while (n_left) {
    // clib_memcpy_fast(&kv, k4, 16);
    clib_bihash_kv_16_8_t kv;
    kv.key[0] = k4->as_u64[0];
    kv.key[1] = k4->as_u64[1];
    // clib_warning("Looking up: %U", format_vcdp_session_key, k4);
    if (sc[0] == VCDP_SERVICE_CHAIN_DROP_NO_KEY) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_LOOKUP_ERROR_NO_KEY];
      vcdp_next(b[0], current_next);
      to_local[n_local] = bi[0];
      n_local++;
      current_next++;
      goto next;
    }
    if (clib_bihash_search_inline_with_hash_16_8(&vcdp->table4, h[0], &kv)) {
      // We can refuse to create session:
      // - Session table is full
      // - Tenant has no-create flag
      // - Can't find key
      // TODO: What about traffic not for VCDP?
      // Some sort of policy lookup required? Unless no-create is set???
      if (no_create || sc[0] > VCDP_SERVICE_CHAIN_TCP) {
        // Not creating sessions for drop or icmp errors
        vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
        b[0]->error = node->errors[VCDP_LOOKUP_ERROR_NO_KEY];
        vcdp_next(b[0], current_next);
        to_local[n_local] = bi[0];
        n_local++;
        current_next++;
        goto next;
      }

      // Miss
      u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
      vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);

      // If local address => ip4-receive
      // 
#if 0
      if (tenant->flags & VCDP_TENANT_FLAG_NO_CREATE)
        return 2;
#endif
      int rv = vcdp_create_session_v4(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k4, vcdp_buffer(b[0])->rx_id, lv, sc[0]);
      switch (rv) {
        case 1: // full
          b[0]->error = node->errors[VCDP_LOOKUP_ERROR_FULL_TABLE];
          vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
          break;
        case 2: // no-create (bypass)
          b[0]->error = node->errors[VCDP_LOOKUP_ERROR_NO_CREATE_SESSION];
          vcdp_buffer(b[0])->service_bitmap = tenant->bitmaps[VCDP_FLOW_FORWARD];
          break;
        case 3: // collision
          vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_COLLISION, 1);
          continue;
      }
      if (rv > 0) {
        vcdp_next(b[0], current_next);
        to_local[n_local] = bi[0];
        n_local++;
        current_next++;
        goto next;
      }
    } else {
      // Hit
      lv[0] = kv.value;
      hit_count++;
    }
    // Figure out if this is local or remote thread
    u32 flow_thread_index = vcdp_thread_index_from_lookup(lv[0]);
    if (flow_thread_index == thread_index) {
      /* known flow which belongs to this thread */
      u32 flow_index = lv[0] & (~(u32) 0);
      to_local[n_local] = bi[0];
      session_index = flow_index >> 1;

      b[0]->flow_id = flow_index;

      session = vcdp_session_at_index(ptd, session_index);
      u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index(flow_index)];

      if (sc[0] == VCDP_SERVICE_CHAIN_ICMP_ERROR) {
        // clib_warning("Setting Service Chain to ICMP ERROR before %U", format_vcdp_bitmap, pbmp);
        pbmp |= VCDP_SERVICE_MASK(nat_icmp_error);
        pbmp &= ~VCDP_SERVICE_MASK(nat_early_rewrite);
        // clib_warning("Setting Service Chain to ICMP ERROR after %U", format_vcdp_bitmap, pbmp);
      }
      vcdp_buffer(b[0])->service_bitmap = pbmp;

      /* The tenant of the buffer is the tenant of the session */
      vcdp_buffer(b[0])->tenant_index = session->tenant_idx;
      vcdp_next(b[0], current_next);
      current_next += 1;
      n_local++;
      session->pkts[vcdp_direction_from_flow_index(flow_index)]++;
      session->bytes[vcdp_direction_from_flow_index(flow_index)] += vlib_buffer_length_in_chain (vm, b[0]);
    } else {
      /* known flow which belongs to remote thread */
      to_remote[n_remote] = bi[0];
      thread_indices[n_remote] = flow_thread_index;
      n_remote++;
    }

    b[0]->flow_id = lv[0] & (~(u32) 0);

    ASSERT(sc[0] != VCDP_SERVICE_CHAIN_DROP_NO_KEY);

  next:
    b += 1;
    n_left -= 1;
    h += 1;
    k4 += 1;
    lv += 1;
    sc += 1;
    bi += 1;
  }

  /* handover buffers to remote node */
  if (n_remote) {
    u32 n_remote_enq;
    n_remote_enq = vlib_buffer_enqueue_to_thread(vm, node, vcdp->frame_queue_index, to_remote, thread_indices, n_remote, 1);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_REMOTE, n_remote_enq);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_CON_DROP, n_remote - n_remote_enq);
  }

  /* enqueue local */
  if (n_local) {
    vlib_buffer_enqueue_to_next(vm, node, to_local, local_next_indices, n_local);
  }

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    bi = from;
    h = hashes;
    u32 *in_local = to_local;
    u32 *in_remote = to_remote;

    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_lookup_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
        t->flow_id = b[0]->flow_id;
        t->hash = h[0];
        if (bi[0] == in_local[0]) {
          t->next_index = local_next_indices[(in_local++) - to_local];
        } else {
          t->next_index = ~0;
          t->remote_worker = thread_indices[(in_remote++) - to_remote];
        }
        if (b[0]->error) {
          t->error = b[0]->error;
        } else {
          t->error = 0;
        }
        if (b[0]->error) {
          t->error = b[0]->error;
        } else {
          t->error = 0;
        }
        clib_memcpy(&t->k4, &keys[i], sizeof(t->k4));
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
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_lookup_inline(vm, node, frame, false);
}

VLIB_NODE_FN(vcdp_lookup_ip4_nocreate_node)(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_lookup_inline(vm, node, frame, true);
}

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

/*
 * next_index is ~0 if the packet was enqueued to the remote node
 * TODO: Handle the case where the lookup fails
 */
static u8 *
format_vcdp_lookup_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_lookup_trace_t *t = va_arg (*args, vcdp_lookup_trace_t *);

  if (t->error)
    s = format(s, "vcdp-lookup (error: %u): ", t->error);
  else if (t->next_index == ~0)
    s = format(s, "vcdp-lookup (handoff: %u): ", t->remote_worker);
  else
    s = format(s, "vcdp-lookup (next index: %u): ", t->next_index);

  s = format(s, "sw_if_index %d, next index %d hash 0x%x "
             "flow-id %u  key 0x%U",
             t->sw_if_index, t->next_index, t->hash, t->flow_id, format_hex_bytes_no_wrap,
             (u8 *) &t->k4, sizeof(t->k4));
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

/*
 * Deleting sessions is done as a pre-input node to ensure it's run at the beginning of a scheduler iteration.
 * This is to ensure that the session is removed before any other nodes are run and buffers are in flight using a
 * removed session.
 */
VLIB_NODE_FN(vcdp_session_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  u32 session_index;

  for (int i=0; vec_len(ptd->expired_sessions) > 0 && i < 256; i++) {
    session_index = vec_pop(ptd->expired_sessions);
    vcdp_session_remove_or_rearm(vcdp, ptd, thread_index, session_index);
  }
  return 0;
}

VLIB_REGISTER_NODE (vcdp_session_expire_node) =
{
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "vcdp-session-expire",
};

VLIB_REGISTER_NODE(vcdp_lookup_ip4_node) = {
  .name = "vcdp-lookup-ip4",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vcdp_lookup_error_counters),
  .error_counters = vcdp_lookup_error_counters,
};

VLIB_REGISTER_NODE(vcdp_lookup_ip4_nocreate_node) = {
  .name = "vcdp-lookup-ip4-nocreate",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vcdp_lookup_error_counters),
  .error_counters = vcdp_lookup_error_counters,
  .sibling_of = "vcdp-lookup-ip4",
};

VLIB_REGISTER_NODE(vcdp_handoff_node) = {
  .name = "vcdp-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vcdp_handoff_error_counters),
  .error_counters = vcdp_handoff_error_counters,
  .sibling_of = "vcdp-lookup-ip4",
};
