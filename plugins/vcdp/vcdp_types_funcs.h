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
  ip4_address_encode2((ip4_address_t *)&skey->src, &out->init_addr);
  ip4_address_encode2((ip4_address_t *)&skey->dst, &out->resp_addr);
  out->init_port = clib_host_to_net_u16(skey->sport);
  out->resp_port = clib_host_to_net_u16(skey->dport);
}

static_always_inline void
vcdp_session_ip6_key_encode(vcdp_session_ip6_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  out->context_id = clib_host_to_net_u32(skey->context_id);
  ip6_address_encode2 (&skey->src, &out->init_addr);
  ip6_address_encode2 (&skey->dst, &out->resp_addr);
  out->init_port = clib_host_to_net_u16(skey->sport);
  out->resp_port = clib_host_to_net_u16(skey->dport);
}

static_always_inline void
vcdp_session_key_encode(vcdp_session_key_flag_t session_type, vcdp_session_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  if (session_type & VCDP_SESSION_KEY_IP4)
    return vcdp_session_ip4_key_encode(&skey->ip4, out);
  if (session_type & VCDP_SESSION_KEY_IP6)
    return vcdp_session_ip6_key_encode(&skey->ip6, out);
}

#endif /*__included_vcdp_types_funcs_h__*/