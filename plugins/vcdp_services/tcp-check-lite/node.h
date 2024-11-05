// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

/*
 * TCP check lite implements parts of the TCP state machine described in RFC7857.
 * To accommodate stateless failover between NATs, it creates sessions like UDP,
 * it is sufficient with a packet seen in each direction to go to ESTABLISHED state.
 * Normal TCP close is used.
 */

#ifndef included_vcdp_tcp_check_lite_node_h
#define included_vcdp_tcp_check_lite_node_h

#include <vlib/vlib.h>
#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/timer_lru.h>

typedef struct {
  u32 flow_id;
  u32 old_state;
  u32 new_state;
} vcdp_tcp_check_lite_trace_t;
format_function_t format_vcdp_tcp_check_session_flags;
format_function_t format_vcdp_tcp_check_lite_state;

u8 *
format_vcdp_tcp_check_lite_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_tcp_check_lite_trace_t *t = va_arg(*args, vcdp_tcp_check_lite_trace_t *);
  u32 indent = format_get_indent(s);
  indent += 2;
  s = format(s, "vcdp-tcp-check-lite: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  if (t->old_state != t->new_state) {
    s = format(s, "  session state changed from: %U to: %U\n", format_vcdp_tcp_check_lite_state, t->old_state, format_vcdp_tcp_check_lite_state, t->new_state);
  } else {
    s = format(s, "  session state: %U\n", format_vcdp_tcp_check_lite_state, t->old_state);
  }
  return s;
}

u8 *format_tcp_flags (u8 * s, va_list * args);
u8 *
format_tcp_flags (u8 * s, va_list * args)
{
  int flags = va_arg (*args, int);

  s = format (s, "0x%02x", flags);
#define _(f) if (flags & TCP_FLAG_##f) s = format (s, " %s", #f);
  foreach_tcp_flag
#undef _
    return s;
}

static u32
vcdp_tcp_state_to_timeout (vcdp_tcp_check_lite_tcp_state_t state)
{
  switch (state) {
    case VCDP_TCP_CHECK_LITE_STATE_CLOSED:
      return VCDP_TIMEOUT_EMBRYONIC;
    case VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED:
      return VCDP_TIMEOUT_TCP_ESTABLISHED;
    case VCDP_TCP_CHECK_LITE_STATE_CLOSING:
      return VCDP_TIMEOUT_TCP_TRANSITORY;
    default:
      return VCDP_TIMEOUT_EMBRYONIC;
  }
}

VCDP_SERVICE_DECLARE(drop)
static_always_inline void
update_state_one_pkt(vcdp_main_t *vcdp, u32 thread_index, vcdp_tenant_t *tenant,
                     vcdp_tcp_check_lite_session_state_t *tcp_session, vcdp_session_t *session, u32 session_index,
                     f64 current_time, u8 dir, vlib_buffer_t **b, u32 *sf, u32 *nsf)
{
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  tcp_header_t *tcp = (tcp_header_t *) (b[0]->data + vnet_buffer(b[0])->l4_hdr_offset);

#if 0
  /* Ignore non first fragments */
  if (ip4_get_fragment_offset(ip4) > 0) {
    vcdp_next(b[0], to_next);
    VCDP_DBG(0, "Fragment ignored");
    return;
  }
#endif

  /* Note: We don't care about SYNs apart from reopening sessions */
  u8 flags = tcp->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_RST);
  u32 next_timeout = vcdp_tcp_state_to_timeout(tcp_session->state);
  if (PREDICT_FALSE(tcp_session->version != session->session_version)) {
    tcp_session->version = session->session_version;
    tcp_session->state = VCDP_TCP_CHECK_LITE_STATE_CLOSED;
    tcp_session->flags[VCDP_FLOW_FORWARD] = 0;
    tcp_session->flags[VCDP_FLOW_REVERSE] = 0;
    next_timeout = vcdp_tcp_state_to_timeout(tcp_session->state);
  }
  sf[0] = nsf[0] = tcp_session->state;

  u8 old_flags = tcp_session->flags[dir];
  tcp_session->flags[dir] |= flags;

  u8 old_state = tcp_session->state;

  /* No change */
  if (old_flags == tcp_session->flags[dir])
    goto out;

  switch (old_state) {
  case VCDP_TCP_CHECK_LITE_STATE_CLOSED:
    // ESTABLISHED when ACKs are seen from both sides
    if ((tcp_session->flags[VCDP_FLOW_FORWARD] & tcp_session->flags[VCDP_FLOW_REVERSE]) & TCP_FLAG_ACK) {
      tcp_session->state = VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED;
      next_timeout = VCDP_TIMEOUT_TCP_ESTABLISHED;
      session->state = VCDP_SESSION_STATE_ESTABLISHED;
    }
    break;
  case VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED:
    // CLOSING when a FIN is seen from either side or session has been RST
    if ((tcp_session->flags[dir] & TCP_FLAG_FIN) || (tcp_session->flags[dir] & TCP_FLAG_RST)) {
      tcp_session->state = VCDP_TCP_CHECK_LITE_STATE_CLOSING;
      tcp_session->flags[VCDP_FLOW_FORWARD] = 0;
      tcp_session->flags[VCDP_FLOW_REVERSE] = 0;
      next_timeout = VCDP_TIMEOUT_TCP_TRANSITORY;
      session->state = VCDP_SESSION_STATE_TIME_WAIT;

    }
    break;
  case VCDP_TCP_CHECK_LITE_STATE_CLOSING:
    // If we see a SYN, we reopen session. It will have the same session id.
    // Otherwise we will just forward against the session until it expires.
    if (tcp_session->flags[VCDP_FLOW_FORWARD] & TCP_FLAG_SYN) {
      VCDP_DBG(2, "Reopening session %U", format_vcdp_session_detail, ptd, session_index, 0);
      u32 thread_index = vlib_get_thread_index();
      vcdp_session_reopen(vcdp, thread_index, session);
      next_timeout = VCDP_TIMEOUT_EMBRYONIC;
      session->state = VCDP_SESSION_STATE_FSOL;
      tcp_session->state = VCDP_TCP_CHECK_LITE_STATE_CLOSED;
      tcp_session->flags[VCDP_FLOW_FORWARD] = 0;
      tcp_session->flags[VCDP_FLOW_REVERSE] = 0;
    }
    break;

    default:
      VCDP_DBG(0, "Unknown state %d", old_state);
  }

out:

  nsf[0] = tcp_session->state;
  vcdp_session_timer_update_timeout_type(vcdp, session, thread_index, next_timeout);
  return;
}

uword
vcdp_tcp_check_lite_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tcp_check_lite_main_t *vtcm = &vcdp_tcp_lite;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vcdp_tcp_check_lite_per_thread_data_t *tptd = vec_elt_at_index(vtcm->ptd, thread_index);
  vcdp_session_t *session;
  vcdp_tenant_t *tenant;
  u32 session_idx;
  vcdp_tcp_check_lite_session_state_t *tcp_session;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 state[VLIB_FRAME_SIZE], *sf = state;
  u32 new_state[VLIB_FRAME_SIZE], *nsf = new_state;
  f64 current_time = vlib_time_now(vm);

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index(ptd, session_idx);
    tcp_session = vec_elt_at_index(tptd->state, session_idx);
    tenant = vcdp_tenant_at_index(vcdp, vcdp_buffer(b[0])->tenant_index);

    /* Ignore IP fragments */
    if (vnet_buffer(b[0])->ip.reass.is_non_first_fragment) {
      VCDP_DBG(0, "Fragment ignored");
      goto next;
    }
    update_state_one_pkt(vcdp, thread_index, tenant, tcp_session, session, session_idx, current_time,
                         vcdp_direction_from_flow_index(b[0]->flow_id), b, sf, nsf);
  next:
    vcdp_next(b[0], to_next);
    n_left -= 1;
    b += 1;
    to_next += 1;
    sf += 1;
    nsf += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    sf = state;
    nsf = new_state;
    n_left = frame->n_vectors;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_tcp_check_lite_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->old_state = sf[0];
        t->new_state = nsf[0];
        b++;
        sf++;
        nsf++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

#endif