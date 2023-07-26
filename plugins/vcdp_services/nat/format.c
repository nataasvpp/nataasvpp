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
  s = format(s, "%u", clib_net_to_host_u16(rewrite->rewrite.sport));
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
  s = format(s, "%u", clib_net_to_host_u16(rewrite->rewrite.dport));
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
    s = format(s, "%s: %U,", str, format_vcdp_nat_rewrite_##sym, rewrite);
  foreach_nat_rewrite_op
#undef _
    if (s && s[vec_len (s) - 1] == ',') {
      s[vec_len(s) - 1] = '\0';
    }
    return s;
}

u8 *
format_vcdp_nat_session(u8 *s, va_list *args)
{
  nat_main_t *nat = &nat_main;
  u32 thread_index = va_arg(*args, u32);
  u32 session_index = va_arg(*args, u32);
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  nat_rewrite_data_t *nat_rewrite = vec_elt_at_index(nptd->flows, session_index);

  s = format(s, "\n  Forward: %U", format_vcdp_nat_rewrite, nat_rewrite[0]);
  s = format(s, "\n  Reverse: %U", format_vcdp_nat_rewrite, nat_rewrite[1]);
  return s;
}
