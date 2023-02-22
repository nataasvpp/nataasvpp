// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>

#define VCDP_NAT_MAX_PORT_ALLOC_RETRIES 5 /* retries to allocate a port */

#define foreach_vcdp_nat_slowpath_error                                             \
  _ (NO_INSTANCE, no_instance, ERROR, "no instance")

typedef enum
{
#define _(f, n, s, d) VCDP_NAT_SLOWPATH_##f,
  foreach_vcdp_nat_slowpath_error
#undef _
    VCDP_NAT_SLOWPATH_N_ERROR,
} vcdp_nat_slowpath_error_t;

static vlib_error_desc_t vcdp_nat_slowpath_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_vcdp_nat_slowpath_error
#undef _
};

typedef struct {
  u32 flow_id;
  u32 thread_index;
} vcdp_nat_slowpath_trace_t;

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
  /* FIXME: This is a scam, the session-idx can be invalid at format time!*/
  vcdp_session_t *session = &ptd->sessions[t->flow_id >> 1];
  s = format(s, "vcdp-nat-output: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  s = format(s, "  new forward service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "  new reverse service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_REVERSE]);

  return s;
}
VCDP_SERVICE_DECLARE(nat_late_rewrite)
VCDP_SERVICE_DECLARE(nat_early_rewrite)
VCDP_SERVICE_DECLARE(nat_output)
VCDP_SERVICE_DECLARE(vcdp_punt)

static_always_inline void
nat_slow_path_process_one(vcdp_main_t *vcdp, vcdp_per_thread_data_t *vptd, /*u32 *fib_index_by_sw_if_index,*/
                          u16 thread_index, nat_main_t *nm, nat_instance_t *instance, u16 nat_idx, u32 session_index,
                          nat_rewrite_data_t *nat_session, vcdp_session_t *session, u16 *to_next, vlib_buffer_t **b)
{
  uword l3_sum_delta_forward = 0;
  uword l4_sum_delta_forward = 0;
  uword l3_sum_delta_reverse = 0;
  uword l4_sum_delta_reverse = 0;
  vcdp_session_ip4_key_t new_key;
  new_key = session->keys[VCDP_SESSION_KEY_PRIMARY];
  u8 proto = session->proto;
  u8 n_retries = 0;
  u32 *ip4_key_src_addr = &new_key.src;
  u32 ip4_old_src_addr;
  u32 ip4_new_src_addr;
  u16 *ip4_key_src_port;
  u16 *ip4_key_dst_port;
  u16 ip4_old_port;
  u16 ip4_new_port;

  u32 src_addr_index;
  u64 h;
  u32 pseudo_flow_index;
  // u32 old_fib_index;

#if 0
  if (PREDICT_FALSE(!(tenant->flags & NAT_TENANT_FLAG_SNAT))) {
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

  pool = pool_elt_at_index(nm->alloc_pool, tenant->out_alloc_pool_idx);
#endif

  if (PREDICT_FALSE(session->session_version == nat_session->version)) {
    /* NAT State is already created, certainly a packet in flight. Refresh
     * bitmap */
    vcdp_buffer(b[0])->service_bitmap = session->bitmaps[b[0]->flow_id & 0x1];
    goto end_of_packet;
  }

#if 0
  /* TODO: handle case with many addresses in pool (slowpath) */
  if (PREDICT_FALSE(pool->num > NAT_ALLOC_POOL_ARRAY_SZ))
    ASSERT(0);
#endif
//  new_key.context_id = tenant->reverse_context;

  /* Allocate a new source */
  ip4_old_src_addr = *ip4_key_src_addr;
  src_addr_index = ip4_old_src_addr % vec_len(instance->addresses);
  ip4_new_src_addr = instance->addresses[src_addr_index].as_u32;
  *ip4_key_src_addr = ip4_new_src_addr;

  pseudo_flow_index = (session_index << 1) | 0x1; // TODO: Always 1, since this is always the return flow

  /* Allocate a new port */
  ip4_key_src_port = &new_key.sport;
  ip4_key_dst_port = &new_key.dport;
  ip4_old_port = *ip4_key_src_port;

  /* First try with original src port */
  ip4_new_port = ip4_old_port;

  // TODO: The secondary key should be added by create session and modified by the NAT node?????
  while ((++n_retries) < VCDP_NAT_MAX_PORT_ALLOC_RETRIES &&
         vcdp_session_try_add_secondary_key(vcdp, vptd, thread_index, pseudo_flow_index, &new_key, &h)) {
    /* Use h to try a different port */
    u32 h2 = h;
    u64 reduced = h2;
    reduced *= 64512ULL;
    reduced >>= 32;
    ip4_new_port = clib_host_to_net_u16(1024 + reduced);
    *ip4_key_src_port = ip4_new_port;
    if (PREDICT_FALSE(proto == IP_PROTOCOL_ICMP))
      *ip4_key_dst_port = ip4_new_port;
  }

  if (n_retries == VCDP_NAT_MAX_PORT_ALLOC_RETRIES) {
    /* Port allocation failure */
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_FAILURES], thread_index, nat_idx, 1);
    goto end_of_packet;
  }
  if (n_retries)
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_RETRIES], thread_index, nat_idx, n_retries);

  /* Build the rewrites in both directions */
  l3_sum_delta_forward = ip_csum_add_even(l3_sum_delta_forward, ip4_new_src_addr);
  l3_sum_delta_forward = ip_csum_sub_even(l3_sum_delta_forward, ip4_old_src_addr);

  l4_sum_delta_forward = ip_csum_add_even(l4_sum_delta_forward, ip4_new_port);
  l4_sum_delta_forward = ip_csum_sub_even(l4_sum_delta_forward, ip4_old_port);

  l3_sum_delta_reverse = ip_csum_add_even(l3_sum_delta_reverse, ip4_old_src_addr);
  l3_sum_delta_reverse = ip_csum_sub_even(l3_sum_delta_reverse, ip4_new_src_addr);

  l4_sum_delta_reverse = ip_csum_add_even(l4_sum_delta_reverse, ip4_old_port);
  l4_sum_delta_reverse = ip_csum_sub_even(l4_sum_delta_reverse, ip4_new_port);

  // old_fib_index = vec_elt(fib_index_by_sw_if_index, vnet_buffer(b[0])->sw_if_index[VLIB_RX]);
  nat_session[0].version = session->session_version;
  nat_session[1].version = session->session_version;

  if (PREDICT_TRUE(proto != IP_PROTOCOL_ICMP)) {
    nat_session[0].ops = NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_SPORT | NAT_REWRITE_OP_TXFIB;
    nat_session[0].rewrite.sport = ip4_new_port;
    nat_session[1].ops = NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_DPORT | NAT_REWRITE_OP_TXFIB;
    nat_session[1].rewrite.dport = ip4_old_port;
  } else {
    nat_session[0].ops = NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_ICMP_ID | NAT_REWRITE_OP_TXFIB;
    nat_session[0].rewrite.icmp_id = ip4_new_port;
    nat_session[1].ops = NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_ICMP_ID | NAT_REWRITE_OP_TXFIB;
    nat_session[1].rewrite.icmp_id = ip4_old_port;
  }

  nat_session[0].rewrite.saddr.as_u32 = ip4_new_src_addr;
//  nat_session[0].rewrite.fib_index = tenant->fib_index;
  nat_session[0].rewrite.proto = proto;
  nat_session[0].l3_csum_delta = l3_sum_delta_forward;
  nat_session[0].l4_csum_delta = l4_sum_delta_forward;

  nat_session[1].rewrite.daddr.as_u32 = ip4_old_src_addr;
//  nat_session[1].rewrite.fib_index = old_fib_index;
  nat_session[1].rewrite.proto = proto;
  nat_session[1].l3_csum_delta = l3_sum_delta_reverse;
  nat_session[1].l4_csum_delta = l4_sum_delta_reverse;

  vcdp_buffer(b[0])->service_bitmap |= VCDP_SERVICE_MASK(nat_late_rewrite);
  session->bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(nat_output);
  session->bitmaps[VCDP_FLOW_REVERSE] &= ~VCDP_SERVICE_MASK(nat_output);
  session->bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(nat_late_rewrite);
  session->bitmaps[VCDP_FLOW_REVERSE] |= VCDP_SERVICE_MASK(nat_early_rewrite);

  nat_session[0].nat_idx = nat_session[1].nat_idx = nat_idx;

end_of_packet:
  vcdp_next(b[0], to_next);
  return;
}

int
vcdp_nat_session_create(u32 session_idx, int instr, u8 proto, ip4_address_t old_addr, u16 old_port,
                        ip4_address_t new_addr, u16 new_port)
{
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, 0); /* Not dealing with threads */
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, 0);
  vcdp_session_t *session;
  nat_rewrite_data_t *nat_session; /* rewrite data in both directions */

  session = vcdp_session_at_index(ptd, session_idx);
  nat_session = vec_elt_at_index(nptd->flows, session_idx << 1);

  uword l3_sum_delta = 0;
  uword l4_sum_delta = 0;

  if (PREDICT_FALSE(session->session_version == nat_session->version)) {
    /* NAT State is already created, certainly a packet in flight. Refresh
     * bitmap */
    // vcdp_buffer(b[0])->service_bitmap = session->bitmaps[b[0]->flow_id & 0x1];
    // goto end_of_packet;
  }

  /* Build the rewrites in both directions */
  l3_sum_delta = ip_csum_add_even(l3_sum_delta, new_addr.as_u32);
  l3_sum_delta = ip_csum_sub_even(l3_sum_delta, old_addr.as_u32);
  l4_sum_delta = ip_csum_add_even(l4_sum_delta, new_port);
  l4_sum_delta = ip_csum_sub_even(l4_sum_delta, old_port);

  nat_session[0].version = session->session_version;

  if (PREDICT_TRUE(proto != IP_PROTOCOL_ICMP)) {
    if (instr == 0) {
      nat_session[0].ops = NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_SPORT;
      nat_session[0].rewrite.sport = new_port; // TODO: Depend on instruction
    } else {
      nat_session[0].ops = NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_DPORT;
      nat_session[0].rewrite.dport = new_port; // TODO: Depend on instruction
    }
  } else {
    if (instr == 0) {
      nat_session[0].ops = NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_ICMP_ID;
    } else {
      nat_session[0].ops = NAT_REWRITE_OP_DADDR | NAT_REWRITE_OP_ICMP_ID;
    }
    nat_session[0].rewrite.icmp_id = new_port;
  }

  if (instr == 0) {
    nat_session[0].rewrite.saddr.as_u32 = new_addr.as_u32;
  } else {
    nat_session[0].rewrite.daddr.as_u32 = new_addr.as_u32;
  }
  nat_session[0].rewrite.proto = proto;
  nat_session[0].l3_csum_delta = l3_sum_delta;
  nat_session[0].l4_csum_delta = l4_sum_delta;

  // Remove punt?
  session->bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(vcdp_punt);
  session->bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(nat_output);
  session->bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(nat_late_rewrite);
  return 0;
}

VLIB_NODE_FN(vcdp_nat_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  // ip4_main_t *im = &ip4_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  vcdp_session_t *session;
  nat_instance_t *instance;
  u32 session_idx;
  u32 tenant_idx;
  u16 nat_idx;
  nat_rewrite_data_t *nat_rewrites; /* rewrite data in both directions */
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index(ptd, session_idx);
    tenant_idx = vcdp_buffer(b[0])->tenant_index;
    nat_rewrites = vec_elt_at_index(nptd->flows, session_idx << 1);
    instance = vcdp_nat_instance_by_tenant_idx(tenant_idx, &nat_idx);
    if (instance) {
      nat_slow_path_process_one(vcdp, ptd, /*im->fib_index_by_sw_if_index,*/ thread_index, nat, instance, nat_idx, session_idx,
                                nat_rewrites, session, to_next, b);
    } else {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_NAT_SLOWPATH_NO_INSTANCE];
      vcdp_next(b[0], to_next);
    }
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

VLIB_REGISTER_NODE(vcdp_nat_slowpath_node) = {.name = "vcdp-nat-output",
                                              .vector_size = sizeof(u32),
                                              .format_trace = format_vcdp_nat_slowpath_trace,
                                              .type = VLIB_NODE_TYPE_INTERNAL,

                                              .n_errors = ARRAY_LEN(vcdp_nat_slowpath_error_counters),
                                              .error_counters = vcdp_nat_slowpath_error_counters,
                                              .sibling_of = "vcdp-lookup-ip4"

};

VCDP_SERVICE_DEFINE(nat_output) = {.node_name = "vcdp-nat-output",
                                   .runs_before = VCDP_SERVICES("vcdp-tunnel-output", "vcdp-nat-late-rewrite"),
                                   .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
                                   .is_terminal = 0};
