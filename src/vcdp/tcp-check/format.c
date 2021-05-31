/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vcdp/vcdp.h>
#include <vcdp/tcp-check/tcp_check.h>

u8 *
format_vcdp_tcp_check_session_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
#define _(name, x, str)                                                       \
  if (flags & VCDP_TCP_CHECK_SESSION_FLAG_##name)                             \
    s = format (s, "%s", (str));
  foreach_vcdp_tcp_check_session_flag
#undef _

    return s;
}

// id tenant index type ingress -> egress flags
u8 *
format_vcdp_tcp_check_session (u8 *s, va_list *args)
{
  vcdp_main_t *vcdp = va_arg (*args, vcdp_main_t *);
  u32 session_index = va_arg (*args, u32);
  vcdp_session_t *session = va_arg (*args, vcdp_session_t *);
  vcdp_tcp_check_session_state_t *tcp_session =
    va_arg (*args, vcdp_tcp_check_session_state_t *);
  vcdp_tenant_t *tenant = vcdp_tenant_at_index (vcdp, session->tenant_idx);
  vcdp_ip4_key_t key;

  /*TODO: deal with secondary keys*/
  vcdp_normalise_key (session, &key, VCDP_SESSION_KEY_PRIMARY);
  u64 session_net = clib_host_to_net_u64 (session->session_id);

  s = format (s, "0x%U\t%d\t%d\t%U\t%U:%u\t-> %U:%u\t%U", format_hex_bytes,
	      &session_net, sizeof (u64), tenant->tenant_id, session_index,
	      format_vcdp_session_type, session->type, format_ip4_address,
	      &key.ip_addr_lo, key.port_lo, format_ip4_address,
	      &key.ip_addr_hi, key.port_hi,
	      format_vcdp_tcp_check_session_flags, tcp_session->flags);

  return s;
}
