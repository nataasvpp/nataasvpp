// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_types_funcs_h
#define included_vcdp_types_funcs_h

#include <vcdp/vcdp.h>
#include <vcdp/vcdp_types.api_types.h>
#include <vcdp/vcdp_types.api_enum.h>
#include <vnet/ip/ip_types_api.h>
static_always_inline u8
vcdp_api_direction(vl_api_vcdp_session_direction_t dir)
{
  switch (dir) {
  case VCDP_API_FORWARD:
    return VCDP_FLOW_FORWARD;
  case VCDP_API_REVERSE:
    return VCDP_API_REVERSE;
  }
  return VCDP_FLOW_FORWARD;
}

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

static_always_inline void
vcdp_session_ip4_key_encode(vcdp_session_ip4_key_t *skey, vl_api_vcdp_session_key_t *out)
{
  ip46_address_t src, dst;
  out->context_id = clib_host_to_net_u32(skey->context_id);
  src.ip4.as_u32 = skey->src;
  dst.ip4.as_u32 = skey->dst;
  out->init_port = clib_host_to_net_u16(skey->sport);
  out->resp_port = clib_host_to_net_u16(skey->dport);
  ip_address_encode(&src, IP46_TYPE_IP4, &out->init_addr);
  ip_address_encode(&dst, IP46_TYPE_IP4, &out->resp_addr);
}

#endif /*__included_vcdp_types_funcs_h__*/