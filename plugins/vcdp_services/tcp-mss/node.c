// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include "tcp_mss.h"
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <vcdp/service.h>

extern vlib_node_registration_t mssc_ip4_in_node, mssc_ip4_out_node;
extern vlib_node_registration_t mssc_ip6_in_node, mssc_ip6_out_node;

typedef struct {
  u32 max_mss;
  u32 org_mss;
  u32 clamped;
} vcdp_tcp_mss_trace_t;

/* packet trace format function */
static u8 *
format_vcdp_tcp_mss_trace(u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_tcp_mss_trace_t *t = va_arg(*args, vcdp_tcp_mss_trace_t *);

  s = format(s, "max mss: %d clamped: %d from: %d", t->max_mss, t->clamped, t->org_mss);
  return s;
}

/*
 * fixup the maximum segment size if it's a syn packet
 * return 1 if the mss was changed otherwise 0
 */
always_inline u32
vcdp_tcp_mss_fixup(tcp_header_t *tcp, u16 max_mss, u16 *org_mss)
{
  ip_csum_t sum;

  u8 opt_len, opts_len, kind;
  u8 *data;
  u16 mss, new_mss;

  opts_len = (tcp_doff(tcp) << 2) - sizeof(tcp_header_t);
  data = (u8 *) (tcp + 1);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len) {
    kind = data[0];

    /* Get options length */
    if (kind == TCP_OPTION_EOL)
      break;
    else if (kind == TCP_OPTION_NOOP) {
      opt_len = 1;
      continue;
    } else {
      /* broken options */
      if (opts_len < 2)
        return 0;
      opt_len = data[1];

      /* weird option length */
      if (opt_len < 2 || opt_len > opts_len)
        return 0;
    }

    if (kind == TCP_OPTION_MSS) {
      mss = *(u16 *) (data + 2);
      if (clib_net_to_host_u16(mss) > max_mss) {
        new_mss = clib_host_to_net_u16(max_mss);
        *((u16 *) (data + 2)) = new_mss;
        sum = tcp->checksum;
        sum = ip_csum_update(sum, mss, new_mss, tcp_header_t, checksum);
        tcp->checksum = ip_csum_fold(sum);
        *org_mss = clib_net_to_host_u16(mss);
        return 1;
      }
    }
  }
  return 0;
}

VCDP_SERVICE_DECLARE(vcdp_tcp_mss);
always_inline uword
vcdp_tcp_mss_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_tcp_mss_main_t *cm = &vcdp_tcp_mss_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;
  u32 pkts_clamped = 0;
  u16 org_mss4 = 0;

  from = vlib_frame_vector_args(frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left);

  while (n_left > 0) {
    ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
    tcp_header_t *tcp = ip4_next_header(ip);
    if (!tcp_syn(tcp))
      goto done;

    u32 clamped;
    u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
    u8 direction = vcdp_direction_from_flow_index(b[0]->flow_id);
    u16 max_mss4 = direction == VCDP_FLOW_FORWARD ? cm->max_mss4_forward[tenant_idx] : cm->max_mss4_reverse[tenant_idx];
    if (max_mss4 == MSS_CLAMP_UNSET)
      goto done;

    clamped = vcdp_tcp_mss_fixup(tcp, max_mss4, &org_mss4);
    pkts_clamped += clamped;

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b[0]->flags & VLIB_BUFFER_IS_TRACED))) {
      vcdp_tcp_mss_trace_t *t;

      t = vlib_add_trace(vm, node, b[0], sizeof(*t));
      t->max_mss = max_mss4;
      t->org_mss = org_mss4;
      t->clamped = clamped;
    }
  done:
    // NB: We don't need to do this anymore, because it will break reopened sessions.
    //
    // If session is established remove ourselves from service chain
    // session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    // session = vcdp_session_at_index(ptd, session_idx);
    // if (session->state == VCDP_SESSION_STATE_ESTABLISHED) {
    //   session->bitmaps[VCDP_FLOW_FORWARD] &= ~VCDP_SERVICE_MASK(vcdp_tcp_mss);
    //   session->bitmaps[VCDP_FLOW_REVERSE] &= ~VCDP_SERVICE_MASK(vcdp_tcp_mss);
    // }

    vcdp_next(b[0], next);

    b++;
    next++;
    n_left--;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);
//  vlib_node_increment_counter(vm, node->node_index, MSS_CLAMP_ERROR_CLAMPED, pkts_clamped);

  return frame->n_vectors;
}

static uword
vcdp_tcp_mss_ip4(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (vcdp_tcp_mss_inline(vm, node, frame));
}

VLIB_REGISTER_NODE(vcdp_tcp_mss_ip4_node) = {
  .function = vcdp_tcp_mss_ip4,
  .name = "vcdp-tcp-mss",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_tcp_mss_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "vcdp-lookup-ip4"
};

VCDP_SERVICE_DEFINE(vcdp_tcp_mss) = {
  .node_name = "vcdp-tcp-mss",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-tcp-check"),
  .is_terminal = 0,
  .is_tcp_specific = 1,
};