// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_types_funcs_h
#define included_vcdp_types_funcs_h

#include <vcdp/vcdp.h>
#include <vcdp/vcdp_types.api_types.h>
#include <vcdp/vcdp_types.api_enum.h>
#include <vnet/ip/ip_types_api.h>
static_always_inline u8
vcdp_api_direction(vl_api_vcdp_session_direction_t dir) {
  switch (dir) {
  case VCDP_API_FORWARD:
    return VCDP_FLOW_FORWARD;
  case VCDP_API_REVERSE:
    return VCDP_API_REVERSE;
  }
  return VCDP_FLOW_FORWARD;
}

static_always_inline vl_api_vcdp_session_type_t
vcdp_session_type_encode(vcdp_session_type_t x) {
  switch (x) {
  case VCDP_SESSION_TYPE_IP4:
    return VCDP_API_SESSION_TYPE_IP4;
  default:
    return -1;
  }
};

static_always_inline u8
vcdp_api_sp_node(vl_api_vcdp_sp_node_t sp_node) {
  switch (sp_node) {
  case VCDP_API_SP_NODE_IP4_REASS:
    return VCDP_SP_NODE_IP4_REASS;

  case VCDP_API_SP_NODE_IP6_REASS:
    return VCDP_SP_NODE_IP6_REASS;

  case VCDP_API_SP_NODE_IP4_UNKNOWN_PROTO:
    return VCDP_SP_NODE_IP4_UNKNOWN_PROTO;

  case VCDP_API_SP_NODE_IP6_UNKNOWN_PROTO:
    return VCDP_SP_NODE_IP6_UNKNOWN_PROTO;

  case VCDP_API_SP_NODE_IP4_ICMP4_ERROR:
    return VCDP_SP_NODE_IP4_ICMP4_ERROR;

  case VCDP_API_SP_NODE_IP6_ICMP6_ERROR:
    return VCDP_SP_NODE_IP6_ICMP6_ERROR;

  default:
    return 0;
  }
}

static_always_inline void
vcdp_session_ip46_key_encode(vcdp_session_ip46_key_t *skey, ip46_type_t type,
                             vl_api_vcdp_session_key_t *out) {
  ip46_address_t ip_addr_lo, ip_addr_hi;
  if (type == IP46_TYPE_IP4) {
    out->context_id = clib_host_to_net_u32(skey->key4.context_id);
    ip_addr_lo.ip4.as_u32 = skey->key4.ip4_key.ip_addr_lo;
    ip_addr_hi.ip4.as_u32 = skey->key4.ip4_key.ip_addr_hi;
    out->init_port = clib_host_to_net_u16(skey->key4.ip4_key.port_lo);
    out->resp_port = clib_host_to_net_u16(skey->key4.ip4_key.port_hi);
  } else {
    out->context_id = clib_host_to_net_u32(skey->key6.context_id);
    ip_addr_lo.ip6 = skey->key6.ip6_key.ip6_addr_lo;
    ip_addr_hi.ip6 = skey->key6.ip6_key.ip6_addr_hi;
    out->init_port = clib_host_to_net_u16(skey->key6.ip6_key.port_lo);
    out->resp_port = clib_host_to_net_u16(skey->key6.ip6_key.port_hi);
  }
  ip_address_encode(&ip_addr_lo, type, &out->init_addr);
  ip_address_encode(&ip_addr_hi, type, &out->resp_addr);
}

#endif /*__included_vcdp_types_funcs_h__*/