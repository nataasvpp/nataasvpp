// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>

u8 *
format_vcdp_tcp_lite_session(u8 *s, va_list *args)
{
  vcdp_tcp_check_lite_session_state_t *tcp_session = va_arg(*args, vcdp_tcp_check_lite_session_state_t *);
  switch (tcp_session->state) {
    case VCDP_TCP_CHECK_LITE_STATE_CLOSED:
      s = format(s, "CLOSED");
      break;
    case VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED: 
      s = format(s, "ESTABLISHED");
      break;
    case VCDP_TCP_CHECK_LITE_STATE_CLOSING:
      s = format(s, "CLOSING");
      break;
    default:
      s = format(s, "UNKNOWN");
      break;
  }
  s = format(s, " flags: F: %x R: %x\n", tcp_session->flags[0], tcp_session->flags[1]);
  return s;
}

u8 *
format_vcdp_tcp_lite_service_session(u8 *s, va_list *args)
{
  u32 session_index = va_arg(*args, u32);
  u32 thread_index = va_arg(*args, u32);

  vcdp_tcp_check_lite_main_t *vtcm = &vcdp_tcp_lite;
  vcdp_tcp_check_lite_session_state_t *tcp_session;
  vcdp_tcp_check_lite_per_thread_data_t *tptd = vec_elt_at_index(vtcm->ptd, thread_index);
  tcp_session = vec_elt_at_index(tptd->state, session_index);

  s = format(s, "%U", format_vcdp_tcp_lite_session, tcp_session);
  return s;
}
