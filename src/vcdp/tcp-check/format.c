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
  u32 ingress_ip4, egress_ip4;
  u16 ingress_port, egress_port;
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  if (session->pseudo_dir)
    {
      ingress_ip4 = session->key.ip4_key.ip_addr_hi;
      egress_ip4 = session->key.ip4_key.ip_addr_lo;
      ingress_port = clib_net_to_host_u16 (session->key.ip4_key.port_hi);
      egress_port = clib_net_to_host_u16 (session->key.ip4_key.port_lo);
    }
  else
    {
      ingress_ip4 = session->key.ip4_key.ip_addr_lo;
      egress_ip4 = session->key.ip4_key.ip_addr_hi;
      ingress_port = clib_net_to_host_u16 (session->key.ip4_key.port_lo);
      egress_port = clib_net_to_host_u16 (session->key.ip4_key.port_hi);
    }
  s = format (s, "0x%U\t%d\t%d\t%U\t%U:%u\t-> %U:%u\t%U", format_hex_bytes,
	      &session_net, sizeof (u64), tenant->tenant_id, session_index,
	      format_vcdp_session_type, session->type, format_ip4_address,
	      &ingress_ip4, ingress_port, format_ip4_address, &egress_ip4,
	      egress_port, format_vcdp_tcp_check_session_flags,
	      tcp_session->flags);

  return s;
}
