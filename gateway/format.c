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

#include <gateway/gateway.h>

u8 *
format_gw_flow (u8 *s, va_list *args)
{
  gw_flow_t *f = va_arg (*args, gw_flow_t *);
  s = format (s, "%U:%u <-> %U:%u", format_ip4_address, &f->ip_addr_lo,
	      clib_net_to_host_u16 (f->port_lo), format_ip4_address,
	      &f->ip_addr_hi, clib_net_to_host_u16 (f->port_hi));
  return s;
}

u8 *
format_gw_flow_with_dir (u8 *s, va_list *args)
{
  gw_flow_t *f = va_arg (*args, gw_flow_t *);
  u32 dir = va_arg (*args, u32);

  if (dir)
    s =
      format (s, "%15U %15u %15U %15u %7u", format_ip4_address, &f->ip_addr_hi,
	      clib_net_to_host_u16 (f->port_hi), format_ip4_address,
	      &f->ip_addr_lo, clib_net_to_host_u16 (f->port_lo), f->proto);
  else
    s =
      format (s, "%15U %15u %15U %15u %7u", format_ip4_address, &f->ip_addr_lo,
	      clib_net_to_host_u16 (f->port_lo), format_ip4_address,
	      &f->ip_addr_hi, clib_net_to_host_u16 (f->port_hi), f->proto);

  return s;
}
