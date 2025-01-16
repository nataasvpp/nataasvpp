// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>

#include <vcdp_services/nat/nat.api_enum.h>

typedef struct {
  u32 flow_id;
  u32 thread_index;
} vcdp_nat_slowpath_trace_t;

typedef struct {
  u32 flow_id;
  u32 thread_index;
} vcdp_nat_port_forwarding_trace_t;

format_function_t format_vcdp_bitmap;

VCDP_SERVICE_DECLARE(drop)
static u8 *
format_vcdp_nat_slowpath_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_nat_slowpath_trace_t *t = va_arg(*args, vcdp_nat_slowpath_trace_t *);
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, t->thread_index);
  if (t->flow_id == ~0)
    return format(s, "vcdp-nat-slowpath: drop");
  vcdp_session_t *session = &ptd->sessions[t->flow_id >> 1];
  s = format(s, "vcdp-nat-slowpath: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  s = format(s, "  new forward service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "  new reverse service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_REVERSE]);

  return s;
}

static u8 *
format_vcdp_nat_port_forwarding_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);

  s = format(s, "vcdp-nat-port-forwarding:");
  // template session:
  // new session:
  return s;
}

static void
nat_rewrites(u32 instructions, u32 oldaddr, u32 newaddr, u16 oldport, u16 newport, u32 new_fib_index, u64 version,
             nat_rewrite_data_t *nat_session)
{
  uword l3_sum_delta = 0;
  uword l4_sum_delta = 0;

  l3_sum_delta = ip_csum_add_even(l3_sum_delta, newaddr);
  l3_sum_delta = ip_csum_sub_even(l3_sum_delta, oldaddr);
  l4_sum_delta = ip_csum_add_even(l4_sum_delta, newport);
  l4_sum_delta = ip_csum_sub_even(l4_sum_delta, oldport);


  // old_fib_index = vec_elt(fib_index_by_sw_if_index, vnet_buffer(b[0])->sw_if_index[VLIB_RX]);
  nat_session->version = version;
  nat_session->ops = instructions;

  if (instructions & NAT_REWRITE_OP_SADDR)
    nat_session->rewrite.saddr.as_u32 = newaddr;
  if (instructions & NAT_REWRITE_OP_DADDR)
    nat_session->rewrite.daddr.as_u32 = newaddr;
  if (instructions & NAT_REWRITE_OP_SPORT)
    nat_session->rewrite.sport = newport;
  if (instructions & NAT_REWRITE_OP_DPORT)
    nat_session->rewrite.dport = newport;
  if (instructions & NAT_REWRITE_OP_ICMP_ID)
    nat_session->rewrite.icmp_id = newport;
  if (instructions & NAT_REWRITE_OP_TXFIB)
    nat_session->rewrite.fib_index = new_fib_index;

  // nat_session->rewrite.proto = proto;
  nat_session->l3_csum_delta = l3_sum_delta;
  nat_session->l4_csum_delta = l4_sum_delta;
}

VCDP_SERVICE_DECLARE(nat_early_rewrite)
VCDP_SERVICE_DECLARE(nat_late_rewrite)

/*
 * Only do SNAT
 */
static_always_inline void
nat_slow_path_process_one(vcdp_main_t *vcdp, vlib_node_runtime_t *node,
                          vcdp_per_thread_data_t *vptd, /*u32 *fib_index_by_sw_if_index,*/
                          u16 thread_index, nat_main_t *nm, nat_instance_t *instance, u16 nat_idx, u32 session_index,
                          nat_rewrite_data_t *nat_session, vcdp_session_t *session, u32 *error, vlib_buffer_t **b)
{
  vcdp_session_key_t new_key = {
    .ip4 = {
    // .dst = session->keys[VCDP_SESSION_KEY_PRIMARY].src,
    .dport = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.sport,
    .proto = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.proto,
    .src = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.dst,
    .sport = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.dport,
    .context_id = instance->context_id,
    },
    .is_ip6 = false,
  };
  u32 fib_index = 0;
  u8 proto = session->proto;
  u8 n_retries = 0;
  u32 ip4_old_src_addr = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.src;
  u16 ip4_old_port = session->keys[VCDP_SESSION_KEY_PRIMARY].ip4.sport;

  u64 h;
  u32 pseudo_flow_index;

  if (PREDICT_FALSE(session->session_version == nat_session->version)) {
    /* NAT State is already created, certainly a packet in flight. Refresh
     * bitmap */
    vcdp_buffer(b[0])->service_bitmap = session->bitmaps[b[0]->flow_id & 0x1];
    goto end_of_packet;
  }

  /* Allocate a new source */
  new_key.ip4.dst = instance->addresses[new_key.ip4.src % vec_len(instance->addresses)].as_u32;

  pseudo_flow_index = (session_index << 1) | 0x1; // Always 1, since this is always the return flow

  while ((++n_retries) < nm->port_retries &&
         vcdp_session_try_add_secondary_key(vcdp, vptd, thread_index, pseudo_flow_index, &new_key, &h)) {
    /* Use h to try a different port */
    u32 h2 = h;
    u64 reduced = h2;
    reduced *= 64512ULL;
    reduced >>= 32;
    new_key.ip4.dport = clib_host_to_net_u16(1024 + reduced);
    if (PREDICT_FALSE(proto == IP_PROTOCOL_ICMP))
      new_key.ip4.sport = new_key.ip4.dport;
  }

  if (n_retries == nm->port_retries) {
    /* Port allocation failure */
    *error = VCDP_NAT_SLOWPATH_ERROR_PORT_ALLOC_FAILURE;
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_FAILURES], thread_index, nat_idx, 1);
    goto end_of_packet;
  }

  if (n_retries > 1)
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_RETRIES], thread_index, nat_idx, n_retries-1);

  /* Build the rewrites in both directions */
  switch (proto) {
  case IP_PROTOCOL_UDP:
  case IP_PROTOCOL_TCP:
    nat_rewrites(NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_SPORT | NAT_REWRITE_OP_TXFIB, ip4_old_src_addr, new_key.ip4.dst,
                 ip4_old_port, new_key.ip4.dport, fib_index, session->session_version, &nat_session[0]);
    nat_rewrites(NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_DPORT | NAT_REWRITE_OP_TXFIB, new_key.ip4.dst, ip4_old_src_addr,
                 ip4_old_port, new_key.ip4.dport, fib_index, session->session_version, &nat_session[1]);
    break;
  case IP_PROTOCOL_ICMP:
    nat_rewrites(NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_ICMP_ID | NAT_REWRITE_OP_TXFIB, ip4_old_src_addr, new_key.ip4.dst,
                 ip4_old_port, new_key.ip4.dport, fib_index, session->session_version, &nat_session[0]);
    nat_rewrites(NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_ICMP_ID | NAT_REWRITE_OP_TXFIB, new_key.ip4.dst, ip4_old_src_addr,
                 ip4_old_port, new_key.ip4.dport, fib_index, session->session_version, &nat_session[1]);
    break;
  default:
    nat_rewrites(NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_TXFIB, ip4_old_src_addr, new_key.ip4.dst,
                 0, 0, fib_index, session->session_version, &nat_session[0]);
    nat_rewrites(NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_TXFIB, ip4_old_src_addr, new_key.ip4.dst,
                 0, 0, fib_index, session->session_version, &nat_session[1]);
  }

  vcdp_buffer(b[0])->service_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];

  nat_session[0].nat_idx = nat_session[1].nat_idx = nat_idx;

end_of_packet:
  return;
}

VLIB_NODE_FN(vcdp_nat_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  nat_instance_t *instance;
  u32 session_idx;
  u32 tenant_idx;
  u16 nat_idx;
  nat_rewrite_data_t *nat_rewrites; /* rewrite data in both directions */
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  vcdp_session_t *session;
  vlib_get_buffers(vm, from, bufs, n_left);

  while (n_left > 0) {
    vcdp_session_key_t k;
    u64 h;
    int rv;
    u32 error = 0;
    u32 flow_index = ~0;
    tenant_idx = vcdp_buffer(b[0])->tenant_index;
    instance = vcdp_nat_instance_by_tenant_idx(tenant_idx, &nat_idx);
    if (!instance) {
      error = VCDP_NAT_SLOWPATH_ERROR_NO_INSTANCE;
      goto next;
    }
    rv = vcdp_calc_key_slow(b[0], vcdp_buffer(b[0])->context_id, &k, &h, false);
    switch (rv) {
    case 0:
      break;
    case -1:
      error = VCDP_NAT_SLOWPATH_ERROR_NO_KEY;
      goto next;
    case -2:
      error = VCDP_NAT_SLOWPATH_ERROR_FRAGMENT;
      goto next;
    case -3:
      error = VCDP_NAT_SLOWPATH_ERROR_TRUNCATED;
      goto next;
    default:
      error = VCDP_NAT_SLOWPATH_ERROR_UNKNOWN;
      goto next;
    }

    /* Check if already created */
    u64 value;
    if (vcdp_lookup_with_hash(h, &k, false, &value) == 0) {
      // ASSERT THAT THIS SESSION IS ON THE SAME THREAD
      vcdp_log_debug("Session already exists for %U sending to fast-path", format_vcdp_session_key, &k);
      u32 flow_thread_index = vcdp_thread_index_from_lookup(value);
      if (flow_thread_index != thread_index) {
        vcdp_log_debug("ERROR: Session %U already exists on thread %d", format_vcdp_session_key, &k, flow_thread_index);
        error = VCDP_NAT_SLOWPATH_ERROR_SESSION;
        goto next;
      }
      /* known flow which belongs to this thread */
      flow_index = value & (~(u32) 0);
      u32 session_index = vcdp_session_from_flow_index(flow_index);
      session = vcdp_session_at_index(ptd, session_index);
      vcdp_buffer(b[0])->service_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];
      goto next;
    }
    session = vcdp_create_session(tenant_idx, &k, 0, false, &flow_index);
    if (!session) {
      error = VCDP_NAT_SLOWPATH_ERROR_SESSION;
      goto next;
    }

    session->bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(nat_early_rewrite);
    session->bitmaps[VCDP_FLOW_REVERSE] |= VCDP_SERVICE_MASK(nat_late_rewrite);

    vcdp_log_debug("Creating session for: %U", format_vcdp_session_key, &k);
    session_idx = session - ptd->sessions;
    nat_rewrites = vec_elt_at_index(nptd->flows, session_idx << 1);
    nat_slow_path_process_one(vcdp, node, ptd, /*im->fib_index_by_sw_if_index,*/ thread_index, nat, instance, nat_idx, session_idx,
                              nat_rewrites, session, &error, b);

    /* Update counters here, since packet is hitting the miss path do not reach the counter in lookup/node.c */
    /* TODO: Use IP length instead of buffer length */
    session->pkts[vcdp_direction_from_flow_index(flow_index)]++;
    session->bytes[vcdp_direction_from_flow_index(flow_index)] += vcdp_get_l3_length(vm, b[0]);

  next:
    if (error) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[error];
    }
    b[0]->flow_id = flow_index;
    vcdp_next(b[0], to_next);
    n_left -= 1;
    b += 1;
    to_next += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    n_left = frame->n_vectors;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_nat_slowpath_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_nat_slowpath_node) = {
  .name = "vcdp-nat-slowpath",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat_slowpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT_SLOWPATH_N_ERROR,
  .error_counters = vcdp_nat_slowpath_error_counters,
};

VCDP_SERVICE_DEFINE(nat_output) = {
  .node_name = "vcdp-nat-slowpath",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};

/*
 * nat_port_forwarding_process_one
 */
static_always_inline void
nat_port_forwarding_process_one(vcdp_main_t *vcdp, vlib_node_runtime_t *node,
                                vcdp_per_thread_data_t *vptd,
                                u16 tenant_idx, u16 thread_index, nat_main_t *nm, nat_port_forwarding_session_t *nat_session,
                                vlib_buffer_t **b, u16 *to_next)
{
  nat_main_t *nat = &nat_main;
  int rv;
  vcdp_session_key_t k;
  u64 h;
  vcdp_session_key_t reverse_k;
  u32 flow_index = ~0;

  rv = vcdp_calc_key_slow(b[0], vcdp_buffer(b[0])->context_id, &k, &h, false);
  if (rv != 0)
    goto error;

  reverse_k.ip4.dst = k.ip4.src;
  reverse_k.ip4.dport = k.ip4.sport;
  reverse_k.ip4.proto = k.ip4.proto;
  reverse_k.ip4.src = nat_session->addr.as_u32;
  reverse_k.ip4.sport = nat_session->port;
  reverse_k.ip4.context_id = 0;
  reverse_k.is_ip6 = false;

  vcdp_session_t *full_session = vcdp_create_session(tenant_idx, &k, &reverse_k, false, &flow_index);
  if (!full_session)
    goto error;

  full_session->bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(nat_early_rewrite);
  full_session->bitmaps[VCDP_FLOW_REVERSE] |= VCDP_SERVICE_MASK(nat_late_rewrite);

  // Create reverse NAT session
  u32 fib_index = 0; // TODO: fix
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  nat_rewrite_data_t *nat_rewrite; /* rewrite data in both directions */
  nat_rewrite = vec_elt_at_index(nptd->flows, (full_session - ptd->sessions) << 1);

  nat_rewrites(NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_DPORT | NAT_REWRITE_OP_TXFIB, k.ip4.dst, reverse_k.ip4.src,
              k.ip4.dport, reverse_k.ip4.sport, fib_index, full_session->session_version, &nat_rewrite[0]);
  nat_rewrites(NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_SPORT | NAT_REWRITE_OP_TXFIB, reverse_k.ip4.src, k.ip4.dst,
               reverse_k.ip4.sport, k.ip4.dport, fib_index, full_session->session_version, &nat_rewrite[1]);

  b[0]->flow_id = flow_index;
  vcdp_buffer(b[0])->service_bitmap = full_session->bitmaps[VCDP_FLOW_FORWARD];
  vcdp_buffer(b[0])->tenant_index = full_session->tenant_idx;
  vcdp_next(b[0], to_next);

  return;

error:
  b[0]->flow_id = flow_index;
  vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
  vcdp_next(b[0], to_next);
  b[0]->error = node->errors[VCDP_NAT_PORT_FORWARDING_ERROR_DROP];
}

static inline void
nat_calc_key_v4_3tuple(ip4_header_t *ip, u32 context_id, nat_3tuple_ip4_key_t *k, u64 *h)
{
  udp_header_t *udp = (udp_header_t *) (ip+1);
  k->proto = ip->protocol;
  k->context_id = context_id;
  k->addr = ip->dst_address.as_u32;
  k->port = udp->dst_port;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (k));
}

static int
vcdp_nat_lookup_3tuple(ip4_header_t *ip, u32 context_id, clib_bihash_kv_16_8_t *kv)
{
  nat_main_t *nat = &nat_main;
  nat_3tuple_ip4_key_t k4 = {};
  u64 h;
  nat_calc_key_v4_3tuple(ip, context_id, &k4, &h);
  kv->key[0] = k4.as_u64[0];
  kv->key[1] = k4.as_u64[1];
  return clib_bihash_search_inline_with_hash_16_8(&nat->port_forwarding, h, kv);
}

VCDP_SERVICE_DECLARE(DROP)
VLIB_NODE_FN(vcdp_nat_port_forwarding_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  nat_port_forwarding_session_t *session;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    clib_bihash_kv_16_8_t kv;
    if (vcdp_nat_lookup_3tuple(vcdp_get_ip4_header(b[0]), vcdp_buffer(b[0])->context_id, &kv)) {
      // Continue down the miss-chain
      vcdp_next(b[0], to_next);
      goto next;
    }

    session = pool_elt_at_index(nat->port_forwarding_sessions, kv.value);
    nat_port_forwarding_process_one(vcdp, node, ptd, session->tenant_idx, thread_index, nat, session, b, to_next);

  next:
    n_left -= 1;
    b += 1;
    to_next += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    n_left = frame->n_vectors;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_nat_port_forwarding_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_nat_port_forwarding_node) = {
  .name = "vcdp-nat-port-forwarding",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat_port_forwarding_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT_PORT_FORWARDING_N_ERROR,
  .error_counters = vcdp_nat_port_forwarding_error_counters,
};

VCDP_SERVICE_DEFINE(nat_port_forwarding) = {
  .node_name = "vcdp-nat-port-forwarding",
  .runs_before = VCDP_SERVICES("vcdp-drop"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};
