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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vcdp/vcdp.api_enum.h>
#include <vcdp/vcdp.api_types.h>
#include <vlibapi/api_helper_macros.h>

static u8
vcdp_api_direction (vl_api_vcdp_session_direction_t dir)
{
  switch (dir)
    {
    case VCDP_API_FORWARD:
      return VCDP_FLOW_FORWARD;
    case VCDP_API_REVERSE:
      return VCDP_API_REVERSE;
    }
  return VCDP_FLOW_FORWARD;
}

static void
vl_api_vcdp_tenant_add_del_t_handler (vl_api_vcdp_tenant_add_del_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 context_id =
    mp->context_id == ~0 ? tenant_id : clib_net_to_host_u32 (mp->context_id);
  u8 is_del = mp->is_del;
  clib_error_t *err =
    vcdp_tenant_add_del (vcdp, tenant_id, context_id, is_del);
  vl_api_vcdp_tenant_add_del_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_VCDP_TENANT_ADD_DEL_REPLY + vcdp->msg_id_base);
}

static void
vl_api_vcdp_set_services_t_handler (vl_api_vcdp_set_services_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 bitmap = clib_net_to_host_u32 (mp->bmp);
  u8 dir = vcdp_api_direction (mp->dir);
  clib_error_t *err = vcdp_set_services (vcdp, tenant_id, bitmap, dir);
  vl_api_vcdp_set_services_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_VCDP_SET_SERVICES_REPLY + vcdp->msg_id_base);
}

static void
vl_api_vcdp_set_timeout_t_handler (vl_api_vcdp_set_timeout_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 timeout_id = clib_net_to_host_u32 (mp->timeout_id);
  u32 timeout_value = clib_net_to_host_u32 (mp->timeout_value);
  clib_error_t *err =
    vcdp_set_timeout (vcdp, tenant_id, timeout_id, timeout_value);
  vl_api_vcdp_set_timeout_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_VCDP_SET_TIMEOUT_REPLY + vcdp->msg_id_base);
}

#include <vcdp/vcdp.api.c>
static clib_error_t *
vcdp_plugin_api_hookup (vlib_main_t *vm)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (vcdp_plugin_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */