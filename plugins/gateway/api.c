// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <gateway/gateway.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/format_fns.h>
#include "tunnel/tunnel.h"
#include <gateway/gateway.api_enum.h>
#include <gateway/gateway.api_types.h>

#define REPLY_MSG_ID_BASE gw->msg_id_base
#include <vlibapi/api_helper_macros.h>

// NOT IMPLEMENTED
static void
vl_api_vcdp_tunnel_create_t_handler(vl_api_vcdp_tunnel_create_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_tunnel_create_reply_t *rmp;
  int rv = 0;
  REPLY_MACRO(VL_API_VCDP_TUNNEL_CREATE_REPLY);
}

// NOT IMPLEMENTED
static void
vl_api_vcdp_tunnel_delete_t_handler(vl_api_vcdp_tunnel_delete_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_tunnel_delete_reply_t *rmp;
  int rv = 0;
  REPLY_MACRO(VL_API_VCDP_TUNNEL_DELETE_REPLY);
}

#include <gateway/gateway.api.c>
static clib_error_t *
vcdp_gateway_api_hookup(vlib_main_t *vm)
{
  gw_main_t *gw = &gateway_main;
  gw->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_gateway_api_hookup);
