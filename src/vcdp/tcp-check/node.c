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
#include <vcdp/tcp-check/tcp_check.h>
#include <vcdp/service.h>
#define foreach_vcdp_tcp_check_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) VCDP_TCP_CHECK_ERROR_##sym,
  foreach_vcdp_tcp_check_error
#undef _
    VCDP_TCP_CHECK_N_ERROR,
} vcdp_tcp_check_error_t;

static char *vcdp_tcp_check_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_tcp_check_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u32 old_state_flags;
  u32 new_state_flags;
} vcdp_tcp_check_trace_t;

static u8 *
format_vcdp_tcp_check_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_tcp_check_trace_t *t = va_arg (*args, vcdp_tcp_check_trace_t *);
  u32 indent = format_get_indent (s);
  indent += 2;
  s = format (s, "vcdp-tcp-check: flow-id %u (session %u, %s)\n", t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  s = format (s, "%Uold session flags: %U\n", format_white_space, indent,
	      format_vcdp_tcp_check_session_flags, t->old_state_flags);
  s = format (s, "%Unew session flags: %U\n", format_white_space, indent,
	      format_vcdp_tcp_check_session_flags, t->new_state_flags);
  return s;
}

static_always_inline void
update_state_one_pkt (vcdp_tw_t *tw,
		      vcdp_tcp_check_session_state_t *tcp_session,
		      vcdp_session_t *session, f64 current_time, u8 dir,
		      u16 *to_next, vlib_buffer_t **b, u32 *sf, u32 *nsf)
{
  /* Parse the packet */
  /* TODO: !!! Broken with IP options !!! */
  u8 *data = vlib_buffer_get_current (b[0]);
  tcp_header_t *tcph = (void *) (data + sizeof (ip4_header_t));
  u8 flags = tcph->flags & VCDP_TCP_CHECK_TCP_FLAGS_MASK;
  u32 acknum = clib_net_to_host_u32 (tcph->ack_number);
  u32 seqnum = clib_net_to_host_u32 (tcph->seq_number);
  u32 next_timeout = 0;
  u8 remove_session = 0;
  if (PREDICT_FALSE (tcp_session->version != session->session_version))
    {
      if (flags != VCDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  /* Abnormal, block the session and drop the packet */
	  session->bitmaps[VCDP_FLOW_FORWARD] = 0x1;
	  session->bitmaps[VCDP_FLOW_REVERSE] = 0x1;
	  vcdp_buffer (b[0])->service_bitmap = 0x1;
	  next_timeout = VCDP_TIMER_SECURITY_TIMER;
	  goto out2;
	}
      tcp_session->version = session->session_version;
      tcp_session->flags = 0;
      tcp_session->as_u64_0 = 0;
    }
  nsf[0] = (sf[0] = tcp_session->flags);
  if (dir == VCDP_FLOW_FORWARD)
    {
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  /* New session, must be a SYN otherwise bad */
	  if (sf[0] == 0)
	    nsf[0] = VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
		     VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
	  else
	    {
	      remove_session = 1;
	      goto out;
	    }
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_ACK)
	{
	  /* Either ACK to SYN */
	  if (sf[0] & VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN)
	    nsf[0] &= ~VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
	  /* Or ACK to FIN */
	  if (sf[0] & VCDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP &&
	      acknum == tcp_session->fin_num[VCDP_FLOW_REVERSE])
	    nsf[0] |= VCDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT;
	  /* Or regular ACK */
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_FIN)
	{
	  /*If we were up, we are not anymore */
	  nsf[0] &= ~VCDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
	  /*Seen our FIN, wait for the other FIN and for an ACK*/
	  tcp_session->fin_num[VCDP_FLOW_FORWARD] = seqnum + 1;
	  nsf[0] |= VCDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT;
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_RST)
	{
	  /* Reason to kill the connection */
	  remove_session = 1;
	  goto out;
	}
    }
  if (dir == VCDP_FLOW_REVERSE)
    {
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  if (sf[0] & VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN)
	    nsf[0] ^= VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
		      VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_ACK)
	{
	  /* Either ACK to SYN */
	  if (sf[0] & VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN)
	    nsf[0] &= ~VCDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
	  /* Or ACK to FIN */
	  if (sf[0] & VCDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT &&
	      acknum == tcp_session->fin_num[VCDP_FLOW_FORWARD])
	    nsf[0] |= VCDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP;
	  /* Or regular ACK */
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_FIN)
	{
	  /*If we were up, we are not anymore */
	  nsf[0] &= ~VCDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
	  /*Seen our FIN, wait for the other FIN and for an ACK*/
	  tcp_session->fin_num[VCDP_FLOW_REVERSE] = seqnum + 1;
	  nsf[0] |= VCDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP;
	}
      if (flags & VCDP_TCP_CHECK_TCP_FLAGS_RST)
	{
	  /* Reason to kill the connection */
	  remove_session = 1;
	  goto out;
	}
    }
  /* If all flags are cleared connection is established! */
  if (nsf[0] == 0)
    {
      nsf[0] = VCDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
      session->state = VCDP_SESSION_STATE_ESTABLISHED;
    }

  /* If all FINs are ACKED, game over */
  if ((nsf[0] & (VCDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT)) &&
      (nsf[0] & VCDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP))
    {
      nsf[0] = VCDP_TCP_CHECK_SESSION_FLAG_TIME_WAIT;
      remove_session = 1;
    }
out:
  tcp_session->flags = nsf[0];
  if (remove_session)
    next_timeout = 0;
  else if (nsf[0] & VCDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED)
    next_timeout = VCDP_TIMER_TCP_ESTABLISHED_TIMEOUT;
  else
    next_timeout = VCDP_TIMER_EMBRYONIC_TIMEOUT;
out2:
  vcdp_session_timer_update_maybe_past (tw, &session->timer, current_time,
					next_timeout);
  vcdp_next (b[0], to_next);
  return;
}

VLIB_NODE_FN (vcdp_tcp_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tcp_check_main_t *vtcm = &vcdp_tcp;
  u32 thread_index = vlib_get_thread_index ();
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);
  vcdp_tcp_check_per_thread_data_t *tptd =
    vec_elt_at_index (vtcm->ptd, thread_index);
  vcdp_session_t *session;
  u32 session_idx;
  vcdp_tcp_check_session_state_t *tcp_session;
  vcdp_tw_t *tw = &ptd->wheel;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 state_flags[VLIB_FRAME_SIZE], *sf = state_flags;
  u32 new_state_flags[VLIB_FRAME_SIZE], *nsf = new_state_flags;
  f64 current_time = ptd->current_time;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      session_idx = vcdp_session_from_flow_index (b[0]->flow_id);
      session = vcdp_session_at_index (ptd, session_idx);
      tcp_session = vec_elt_at_index (tptd->state, session_idx);
      if (vcdp_direction_from_flow_index (b[0]->flow_id) == VCDP_FLOW_FORWARD)
	update_state_one_pkt (tw, tcp_session, session, current_time,
			      VCDP_FLOW_FORWARD, to_next, b, sf, nsf);
      else
	update_state_one_pkt (tw, tcp_session, session, current_time,
			      VCDP_FLOW_REVERSE, to_next, b, sf, nsf);
      n_left -= 1;
      b += 1;
      to_next += 1;
      sf += 1;
      nsf += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      sf = state_flags;
      nsf = new_state_flags;
      n_left = frame->n_vectors;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_tcp_check_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->old_state_flags = sf[0];
	      t->new_state_flags = nsf[0];
	      b++;
	      sf++;
	      nsf++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vcdp_tcp_check_node) = {
  .name = "vcdp-tcp-check",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_tcp_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_tcp_check_error_strings),
  .error_strings = vcdp_tcp_check_error_strings,
  .sibling_of = "vcdp-lookup"

};