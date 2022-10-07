// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <gateway/gateway.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include "tunnel.h"
#include <vnet/format_fns.h>
#include <tunnel/tunnel.api_enum.h>
#include <tunnel/tunnel.api_types.h>

#define REPLY_MSG_ID_BASE tm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_tunnel_create_t_handler(
  vl_api_vcdp_tunnel_create_t *mp) {
  vl_api_vcdp_tunnel_create_reply_t *rmp;
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  int rv = 0;
#if 0
  gw_set_geneve_output_args_t args;
  args.tenant_id = clib_net_to_host_u32(mp->tenant_id);
  ASSERT(mp->src.af == ADDRESS_IP4);
  ASSERT(mp->dst.af == ADDRESS_IP4);
  ip4_address_decode(mp->src.un.ip4, &args.src_addr);
  ip4_address_decode(mp->dst.un.ip4, &args.dst_addr);
  args.src_port = mp->src_port;
  args.dst_port = mp->dst_port;
  args.direction = mp->dir;
  args.static_mac = mp->static_mac;
  args.output_tenant_id = clib_net_to_host_u32(mp->output_tenant_id);
  mac_address_decode(mp->src_mac, &args.src_mac);
  mac_address_decode(mp->dst_mac, &args.dst_mac);
  gw_set_geneve_output(&args);
  rv = args.err ? -1 : 0;
#endif
  REPLY_MACRO(VL_API_VCDP_TUNNEL_CREATE_REPLY);
}

static void
vl_api_vcdp_tunnel_delete_t_handler(
  vl_api_vcdp_tunnel_delete_t *mp) {
  vl_api_vcdp_tunnel_delete_reply_t *rmp;
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  int rv = 0;
#if 0
  gw_enable_disable_geneve_input_args_t args;
  args.enable_disable = mp->is_enable;
  args.sw_if_index = clib_net_to_host_u32(mp->sw_if_index);
  gw_enable_disable_geneve_input(&args);
  rv = args.err ? -1 : 0;
#endif
  REPLY_MACRO(VL_API_VCDP_TUNNEL_DELETE_REPLY);
}

#include <tunnel/tunnel.api.c>
static clib_error_t *
vcdp_tunnel_api_hookup(vlib_main_t *vm) {
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  tm->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_tunnel_api_hookup);
