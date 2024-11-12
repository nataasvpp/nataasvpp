// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_types_funcs_h
#define included_vcdp_types_funcs_h

#include <vcdp/vcdp.h>
#include <vcdp/vcdp_types.api_types.h>
#include <vcdp/vcdp_types.api_enum.h>
#include <vnet/ip/ip_types_api.h>

static_always_inline vl_api_vcdp_session_type_t
vcdp_session_type_encode(vcdp_session_type_t x)
{
  switch (x) {
  case VCDP_SESSION_TYPE_IP4:
    return VCDP_API_SESSION_TYPE_IP4;
  default:
    return -1;
  }
};

void
ip4_address_encode2 (const ip4_address_t * a, vl_api_address_t * out)
{
  out->af = ADDRESS_IP4;
  clib_memcpy (out->un.ip4, a->as_u8, sizeof (out->un.ip4));
}
void
ip6_address_encode2 (const ip6_address_t * a, vl_api_address_t * out)
{
  out->af = ADDRESS_IP6;
  clib_memcpy (out->un.ip6, a->as_u8, sizeof (out->un.ip6));
}

static_always_inline void
vcdp_session_ip4_key_encode(vcdp_session_ip4_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  out->context_id = clib_host_to_net_u32(skey->context_id);
  ip4_address_encode2((ip4_address_t *)&skey->src, &out->src);
  ip4_address_encode2((ip4_address_t *)&skey->dst, &out->dst);
  out->sport = clib_host_to_net_u16(skey->sport);
  out->dport = clib_host_to_net_u16(skey->dport);
}

static_always_inline void
vcdp_session_ip6_key_encode(vcdp_session_ip6_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  out->context_id = clib_host_to_net_u32(skey->context_id);
  ip6_address_encode2 (&skey->src, &out->src);
  ip6_address_encode2 (&skey->dst, &out->dst);
  out->sport = clib_host_to_net_u16(skey->sport);
  out->dport = clib_host_to_net_u16(skey->dport);
  out->proto = skey->proto;
}

static_always_inline void
vcdp_session_key_encode(vcdp_session_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  if (skey->is_ip6)
    return vcdp_session_ip6_key_encode(&skey->ip6, out);
  else
    return vcdp_session_ip4_key_encode(&skey->ip4, out);
}

static_always_inline void
vcdp_session_key_decode(vl_api_vcdp_session_key_t *in, vcdp_session_key_t *out)
{
  ip_address_t src, dst;
  ip_address_decode2(&in->src, &src);
  ip_address_decode2(&in->dst, &dst);
  clib_memset(out, 0, sizeof(*out));
  if (src.version ==  AF_IP6) {
    vcdp_session_ip6_key_t *out6 = &out->ip6;
    out6->context_id = in->context_id;
    out6->src = src.ip.ip6;
    out6->dst = dst.ip.ip6;
    out6->sport = clib_host_to_net_u16(in->sport);
    out6->dport = clib_host_to_net_u16(in->dport);
    out6->proto = in->proto;
    out->is_ip6 = true;
  } else {
    vcdp_session_ip4_key_t *out4 = &out->ip4;
    out4->context_id = in->context_id;
    out4->src = src.ip.ip4.as_u32;
    out4->dst = dst.ip.ip4.as_u32;
    out4->sport = clib_host_to_net_u16(in->sport);
    out4->dport = clib_host_to_net_u16(in->dport);
    out4->proto = in->proto;
    out->is_ip6 = false;
  }
}

#endif /*__included_vcdp_types_funcs_h__*/