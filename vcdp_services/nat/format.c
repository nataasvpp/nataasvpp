// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/nat/nat.h>

static u8 *
format_vcdp_nat_rewrite_SADDR(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "%U", format_ip4_address, &rewrite->rewrite.saddr);
  return s;
}

static u8 *
format_vcdp_nat_rewrite_SPORT(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "%u", (unsigned int)clib_net_to_host_u16(rewrite->rewrite.sport));
  return s;
}

static u8 *
format_vcdp_nat_rewrite_DADDR(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "%U", format_ip4_address, &rewrite->rewrite.daddr);
  return s;
}
static u8 *
format_vcdp_nat_rewrite_DPORT(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "%u", (unsigned int)clib_net_to_host_u16(rewrite->rewrite.dport));
  return s;
}
static u8 *
format_vcdp_nat_rewrite_ICMP_ID(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "%u", rewrite->rewrite.icmp_id);
  return s;
}
static u8 *
format_vcdp_nat_rewrite_TXFIB(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
  s = format(s, "fib-index %u", rewrite->rewrite.fib_index);
  return s;
}

u8 *
format_vcdp_nat_rewrite(u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg(*args, nat_rewrite_data_t *);
#define _(sym, x, str)                                                                                                 \
  if (rewrite->ops & NAT_REWRITE_OP_##sym)                                                                             \
    s = format(s, "rewrite %s (to %U),", str, format_vcdp_nat_rewrite_##sym, rewrite);
  foreach_nat_rewrite_op
#undef _
    // if (s && s[vec_len (s) - 1] == ',') vec_resize (s, vec_len (s) - 1);
    return s;
}

u8 *
format_vcdp_nat64_rewrite(u8 *s, va_list *args)
{
  nat64_rewrite_data_t *rewrite = va_arg(*args, nat64_rewrite_data_t *);

  if (rewrite->ops & NAT64_REWRITE_OP_HDR_64)
    s = format(s, "rewrite hdr64 (to %U),", format_ip4_header, &rewrite->ip4, 20);
  if (rewrite->ops & NAT64_REWRITE_OP_HDR_46)
    s = format(s, "rewrite hdr46 (to %U),", format_ip6_header, &rewrite->ip6, 40);
  return s;
}

u8 *
format_vcdp_nat_instance(u8 *s, va_list *args)
{
  u16 *nat_idx = va_arg(*args, u16 *);
  nat_instance_t *instance = vec_elt_at_index(nat_main.instances, *nat_idx);
  return format(s, "%s", instance->nat_id);
}

u8 *
format_vcdp_nat_service(u8 *s, u32 thread_index, u32 session_index)
{
  nat_main_t *nat = &nat_main;
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  nat_rewrite_data_t *nat_rewrite = vec_elt_at_index(nptd->flows, session_index << 1);
  s = format(s, "  nat forward: %U\n", format_vcdp_nat_rewrite, &nat_rewrite[0]);
  s = format(s, "      reverse: %U\n", format_vcdp_nat_rewrite, &nat_rewrite[1]);
  s = format(s, "      instance: %U\n", format_vcdp_nat_instance, &nat_rewrite[0].nat_idx);
  return s;
}

u8 *
format_vcdp_nat64_service(u8 *s, u32 thread_index, u32 session_index)
{
  nat_main_t *nat = &nat_main;
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  nat64_rewrite_data_t *nat_rewrite = vec_elt_at_index(nptd->flows64, session_index << 1);
  s = format(s, "  nat forward: %U\n", format_vcdp_nat64_rewrite, &nat_rewrite[0]);
  s = format(s, "      reverse: %U\n", format_vcdp_nat64_rewrite, &nat_rewrite[1]);
  return s;
}
