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
} vcdp_nat64_slowpath_trace_t;

format_function_t format_vcdp_bitmap;

VCDP_SERVICE_DECLARE(drop)
static u8 *
format_vcdp_nat64_slowpath_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_nat64_slowpath_trace_t *t = va_arg(*args, vcdp_nat64_slowpath_trace_t *);
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, t->thread_index);
  if (t->flow_id == ~0)
    return format(s, "vcdp-nat64-slowpath: drop");
  vcdp_session_t *session = &ptd->sessions[t->flow_id >> 1];
  s = format(s, "vcdp-nat64-slowpath: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  s = format(s, "  new forward service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "  new reverse service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_REVERSE]);

  return s;
}


static u32
nat64_get_v4(ip6_address_t *a)
{
  return a->as_u32[3];
}

static_always_inline void
nat64_slow_path_process_one(vcdp_main_t *vcdp, vlib_node_runtime_t *node,
                          vcdp_per_thread_data_t *vptd, /*u32 *fib_index_by_sw_if_index,*/
                          u16 thread_index, nat_main_t *nm, nat_instance_t *instance, u16 nat_idx, u32 session_index,
                          nat64_rewrite_data_t *nat_session, vcdp_session_t *session, u32 *error, vlib_buffer_t **b)
{
  u16 old_sport = session->keys[VCDP_SESSION_KEY_PRIMARY].ip6.sport;
  vcdp_session_key_t new_key = {
    .ip4 = {
      .dport = session->keys[VCDP_SESSION_KEY_PRIMARY].ip6.sport,
      .proto = session->keys[VCDP_SESSION_KEY_PRIMARY].ip6.proto,
      .src = nat64_get_v4(&session->keys[VCDP_SESSION_KEY_PRIMARY].ip6.dst),
      .sport = session->keys[VCDP_SESSION_KEY_PRIMARY].ip6.dport,
      .context_id = instance->context_id,
    },
    .is_ip6 = false,
  };
  // u32 fib_index = 0;
  u8 proto = session->proto;
  u8 n_retries = 0;
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
  u8 v4proto = proto == IP_PROTOCOL_ICMP6 ? IP_PROTOCOL_ICMP : proto;
  new_key.ip4.proto = v4proto;

  if (v4proto == IP_PROTOCOL_TCP || v4proto == IP_PROTOCOL_UDP || v4proto == IP_PROTOCOL_ICMP) {
    while ((++n_retries) < nm->port_retries &&
           vcdp_session_try_add_secondary_key(vcdp, vptd, thread_index, pseudo_flow_index, &new_key, &h)) {
      /* Use h to try a different port */
      u32 h2 = h;
      u64 reduced = h2;
      reduced *= 64512ULL;
      reduced >>= 32;
      new_key.ip4.dport = clib_host_to_net_u16(1024 + reduced);
      if (v4proto == IP_PROTOCOL_ICMP)
        new_key.ip4.sport = new_key.ip4.dport;
    }
  } else {
    /* Fall back to 3-tuple for non TCP/UDP/ICMP sessions */
    vcdp_session_try_add_secondary_key(vcdp, vptd, thread_index, pseudo_flow_index, &new_key, &h);
  }

  if (n_retries == nm->port_retries) {
    /* Port allocation failure */
    *error = VCDP_NAT_SLOWPATH_ERROR_PORT_ALLOC_FAILURE;
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_FAILURES], thread_index, nat_idx, 1);
    goto end_of_packet;
  }

  if (n_retries > 1) {
    nat_session[0].ops = NAT64_REWRITE_OP_SPORT;
    nat_session[0].sport = new_key.ip4.dport;
    nat_session[1].ops = NAT64_REWRITE_OP_DPORT;
    nat_session[1].dport = old_sport;
    vlib_increment_simple_counter(&nm->simple_counters[VCDP_NAT_COUNTER_PORT_ALLOC_RETRIES], thread_index, nat_idx,
                                  n_retries - 1);
  }
  ip6_header_t *ip6 = vcdp_get_ip6_header(b[0]);
  nat_session[0].ip4.ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;    //0x45;
  nat_session[0].ip4.tos = 0;
  nat_session[0].ip4.length = 0;
  nat_session[0].ip4.fragment_id = 0;
  nat_session[0].ip4.flags_and_fragment_offset = 0;
  nat_session[0].ip4.ttl = 0;
  nat_session[0].ip4.protocol = v4proto;
  nat_session[0].ip4.checksum = 0;
  nat_session[0].ip4.src_address.as_u32 = new_key.ip4.dst;
  nat_session[0].ip4.dst_address.as_u32 = new_key.ip4.src;

  nat_session[0].version = session->session_version;
  nat_session[0].ops |= NAT64_REWRITE_OP_HDR_64;

  nat_session[1].ip6.ip_version_traffic_class_and_flow_label = 0x60;
  nat_session[1].ip6.hop_limit = 0;
  nat_session[1].ip6.protocol = proto;
  nat_session[1].ip6.src_address.as_u64[0] = ip6->dst_address.as_u64[0];
  nat_session[1].ip6.src_address.as_u64[1] = ip6->dst_address.as_u64[1];
  nat_session[1].ip6.dst_address.as_u64[0] = ip6->src_address.as_u64[0];
  nat_session[1].ip6.dst_address.as_u64[1] = ip6->src_address.as_u64[1];
  nat_session[1].version = session->session_version;
  nat_session[1].ops |= NAT64_REWRITE_OP_HDR_46;

  VCDP_DBG(3, "Creating a mapping between %U and %U", format_ip4_header, &nat_session[0].ip4, sizeof(ip4_header_t),
           format_ip6_header, &nat_session[1].ip6, sizeof(ip6_header_t));

  vcdp_buffer(b[0])->service_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];

  nat_session[0].nat_idx = nat_session[1].nat_idx = nat_idx;
end_of_packet:
  return;
}

VCDP_SERVICE_DECLARE(drop)
VCDP_SERVICE_DECLARE(nat64_early_rewrite)
VCDP_SERVICE_DECLARE(nat64_late_rewrite)
VLIB_NODE_FN(vcdp_nat64_slowpath_node)
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
  nat64_rewrite_data_t *nat_rewrites; /* rewrite data in both directions */
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);

  while (n_left > 0) {
    vcdp_session_key_t k;
    u64 h;
    u32 error = 0;
    vcdp_session_t *session;
    u32 flow_index = ~0;

    tenant_idx = vcdp_buffer(b[0])->tenant_index;
    instance = vcdp_nat_instance_by_tenant_idx(tenant_idx, &nat_idx);
    if (!instance) {
      error = VCDP_NAT_SLOWPATH_ERROR_NO_INSTANCE;
      goto next;
    }
    int rv = vcdp_calc_key_slow(b[0], vcdp_buffer(b[0])->context_id, &k, &h, true);
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
    if (vcdp_lookup_with_hash(h, &k, true, &value) == 0) {
      // ASSERT THAT THIS SESSION IS ON THE SAME THREAD
      VCDP_DBG(3, "Session already exists for %U sending to fast-path", format_vcdp_session_key, &k);
      u32 flow_thread_index = vcdp_thread_index_from_lookup(value);
      if (flow_thread_index != thread_index) {
        VCDP_DBG(0, "ERROR: Session %U already exists on thread %d", format_vcdp_session_key, &k, flow_thread_index);
        error = VCDP_NAT_SLOWPATH_ERROR_SESSION;
        goto next;
      }
      /* known flow which belongs to this thread */
      flow_index = value & (~(u32) 0);
      u32 session_index = vcdp_session_from_flow_index(flow_index);
      b[0]->flow_id = flow_index;
      session = vcdp_session_at_index(ptd, session_index);
      vcdp_buffer(b[0])->service_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];
      goto next;
    }

      session = vcdp_create_session(tenant_idx, &k, 0, false, &flow_index);
      if (!session) {
        error = VCDP_NAT_SLOWPATH_ERROR_SESSION;
        goto next;
      }
      session->bitmaps[VCDP_FLOW_FORWARD] |= VCDP_SERVICE_MASK(nat64_early_rewrite);
      session->bitmaps[VCDP_FLOW_REVERSE] |= VCDP_SERVICE_MASK(nat64_late_rewrite);

      session_idx = session - ptd->sessions;
      session->type = VCDP_SESSION_TYPE_NAT64;
      nat_rewrites = vec_elt_at_index(nptd->flows64, session_idx << 1);
      nat64_slow_path_process_one(vcdp, node, ptd, /*im->fib_index_by_sw_if_index,*/ thread_index, nat, instance,
                                  nat_idx, session_idx, nat_rewrites, session, &error, b);

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
        vcdp_nat64_slowpath_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_nat64_slowpath_node) = {
  .name = "vcdp-nat64-slowpath",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat64_slowpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT_SLOWPATH_N_ERROR,
  .error_counters = vcdp_nat_slowpath_error_counters,
};

VCDP_SERVICE_DEFINE(nat64_output) = {
  .node_name = "vcdp-nat64-slowpath",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};
