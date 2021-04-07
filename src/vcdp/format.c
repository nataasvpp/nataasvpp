/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>

#include <vcdp/vcdp.h>

u8 *
format_vcdp_session_state (u8 *s, va_list *args)
{
  u8 session_state = va_arg (*args, u32);
#define _(n, str)                                                             \
  if (session_state == VCDP_SESSION_STATE_##n)                                \
    s = format (s, "%s", (str));
  foreach_vcdp_session_state
#undef _
    return s;
}

u8 *
format_vcdp_session_type (u8 *s, va_list *args)
{
  u32 session_type = va_arg (*args, u32);
  if (session_type == VCDP_SESSION_TYPE_IP4)
    s = format (s, "ipv4");
  return s;
}

/* Tenant Session_index Session_Type Protocol Ingress -> Egress State
 * TTL(seconds) */
u8 *
format_vcdp_session (u8 *s, va_list *args)
{
  u32 session_index = va_arg (*args, u32);
  vcdp_session_t *session = va_arg (*args, vcdp_session_t *);
  f64 now = va_arg (*args, f64);
  f64 remaining_time = session->next_expiration - now;
  u32 ingress_ip4, egress_ip4;
  u16 ingress_port, egress_port;
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  if ((session->key.ip4_key.proto == IP_PROTOCOL_UDP ||
       session->key.ip4_key.proto == IP_PROTOCOL_TCP) &&
      session->pseudo_dir)
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
  s = format (s, "0x%U\t%d\t%d\t%U\t%U\t%U:%u\t-> %U:%u\t%U\t%f",
	      format_hex_bytes, &session_net, sizeof (u64),
	      session->key.tenant_id, session_index, format_vcdp_session_type,
	      session->type, format_ip_protocol, session->key.ip4_key.proto,
	      format_ip4_address, &ingress_ip4, ingress_port,
	      format_ip4_address, &egress_ip4, egress_port,
	      format_vcdp_session_state, session->state, remaining_time);
  return s;
}
