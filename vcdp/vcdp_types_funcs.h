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
#if 0
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
#endif
static_always_inline void
vcdp_session_key_encode(vcdp_session_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  out->context_id = clib_host_to_net_u32(skey->context_id);
  ip_address_encode (&skey->src, ip46_address_get_type(&skey->src), &out->src);
  ip_address_encode (&skey->dst, ip46_address_get_type(&skey->dst), &out->dst);
  out->sport = clib_host_to_net_u16(skey->sport);
  out->dport = clib_host_to_net_u16(skey->dport);
  out->proto = skey->proto;
}

static_always_inline void
vcdp_session_key_decode(vl_api_vcdp_session_key_t *in, vcdp_session_key_t *out)
{
  ip46_address_t src, dst;
  ip_address_decode(&in->src, &src);
  ip_address_decode(&in->dst, &dst);
  clib_memset(out, 0, sizeof(*out));
    out->context_id = in->context_id;
    out->src = src;
    out->dst = dst;
    out->sport = clib_host_to_net_u16(in->sport);
    out->dport = clib_host_to_net_u16(in->dport);
    out->proto = in->proto;
}

#endif /*__included_vcdp_types_funcs_h__*/