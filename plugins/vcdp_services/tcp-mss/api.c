// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vnet/vnet.h>
#include "tcp_mss.h"
#include "vcdp_services/tcp-mss/tcp_mss.api_enum.h"
#include "vcdp_services/tcp-mss/tcp_mss.api_types.h"
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void
vl_api_vcdp_tcp_mss_enable_disable_t_handler (vl_api_vcdp_tcp_mss_enable_disable_t *mp)
{
  vcdp_tcp_mss_main_t *cm = &vcdp_tcp_mss_main;
  vl_api_vcdp_tcp_mss_enable_disable_reply_t *rmp;
  int rv;

  rv = vcdp_tcp_mss_enable_disable(mp->tenant_id, mp->ip4_mss[0], mp->ip4_mss[1], mp->is_enable);

  REPLY_MACRO_END (VL_API_VCDP_TCP_MSS_ENABLE_DISABLE_REPLY);
}

static void
vl_api_vcdp_tcp_mss_defaults_t_handler (vl_api_vcdp_tcp_mss_defaults_t *mp)
{
  vcdp_tcp_mss_main_t *cm = &vcdp_tcp_mss_main;
  vl_api_vcdp_tcp_mss_defaults_reply_t *rmp;
  int rv = 0;

  vcdp_tcp_mss_defaults(mp->ip4_mss[0], mp->ip4_mss[1]);

  REPLY_MACRO_END (VL_API_VCDP_TCP_MSS_DEFAULTS_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <vcdp_services/tcp-mss/tcp_mss.api.c>

/* Set up the API message handling tables */
static clib_error_t *
vcdp_tcp_mss_api_hookup (vlib_main_t *vm)
{
  vcdp_tcp_mss_main_t *cm = &vcdp_tcp_mss_main;

  cm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (vcdp_tcp_mss_api_hookup);
