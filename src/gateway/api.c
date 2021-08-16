/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vcdp/vcdp.h>

#include <gateway/gateway.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/format_fns.h>
#include <gateway/gateway.api_enum.h>
#include <gateway/gateway.api_types.h>
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_gateway_set_geneve_output_t_handler (
  vl_api_vcdp_gateway_set_geneve_output_t *mp)
{
  gw_main_t *gw = &gateway_main;
  int rv;
  vl_api_vcdp_gateway_set_geneve_output_reply_t *rmp;
  gw_set_geneve_output_args_t args;
  args.tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  ip4_address_decode (mp->src, &args.src_addr);
  ip4_address_decode (mp->dst, &args.dst_addr);
  args.src_port = mp->src_port;
  args.dst_port = mp->dst_port;
  args.direction = mp->dir;
  args.static_mac = mp->static_mac;
  args.output_tenant_id = clib_net_to_host_u32 (mp->output_tenant_id);
  mac_address_decode (mp->src_mac, &args.src_mac);
  mac_address_decode (mp->dst_mac, &args.dst_mac);
  gw_set_geneve_output (&args);
  rv = args.err ? -1 : 0;
  REPLY_MACRO (VL_API_VCDP_GATEWAY_SET_GENEVE_OUTPUT_REPLY + gw->msg_id_base);
}

static void
vl_api_vcdp_gateway_geneve_input_enable_disable_t_handler (
  vl_api_vcdp_gateway_geneve_input_enable_disable_t *mp)
{
  gw_main_t *gw = &gateway_main;
  int rv;
  vl_api_vcdp_gateway_geneve_input_enable_disable_reply_t *rmp;
  gw_enable_disable_geneve_input_args_t args;
  args.enable_disable = mp->is_enable;
  args.sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  gw_enable_disable_geneve_input (&args);
  rv = args.err ? -1 : 0;
  REPLY_MACRO (VL_API_VCDP_GATEWAY_GENEVE_INPUT_ENABLE_DISABLE_REPLY +
	       gw->msg_id_base);
}

#include <gateway/gateway.api.c>
static clib_error_t *
vcdp_gateway_api_hookup (vlib_main_t *vm)
{
  gw_main_t *gw = &gateway_main;
  gw->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (vcdp_gateway_api_hookup);