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
#include <vcdp/tcp-check/tcp_check.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vcdp/tcp-check/tcp_check.api_enum.h>
#include <vcdp/tcp-check/tcp_check.api_types.h>
#include <vlibapi/api_helper_macros.h>

#include <vcdp/vcdp_types_funcs.h>

static u32
vcdp_tcp_check_session_flags_encode (u32 x)
{
  return clib_host_to_net_u32 (x);
};

static void
vcdp_tcp_send_session_details (vl_api_registration_t *rp, u32 context,
			       u32 session_index, u32 thread_index,
			       vcdp_session_t *session,
			       vcdp_tcp_check_session_state_t *tcp_session)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tcp_check_main_t *tcp = &vcdp_tcp;
  vl_api_vcdp_tcp_session_details_t *mp;
  vcdp_ip4_key_t key;
  vcdp_tenant_t *tenant;
  u32 tenant_id;
  size_t msg_size;
  u8 n_keys = vcdp_session_n_keys (session);
  tenant = vcdp_tenant_at_index (vcdp, session->tenant_idx);
  tenant_id = tenant->tenant_id;
  msg_size = sizeof (*mp) + sizeof (mp->keys[0]) * n_keys;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_VCDP_TCP_SESSION_DETAILS + tcp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->session_id = clib_host_to_net_u64 (session->session_id);
  mp->thread_index = clib_host_to_net_u32 (thread_index);
  mp->tenant_id = clib_host_to_net_u32 (tenant_id);
  mp->session_idx = clib_host_to_net_u32 (session_index);
  mp->session_type = vcdp_session_type_encode (session->type);
  mp->flags = vcdp_tcp_check_session_flags_encode (tcp_session->flags);
  mp->n_keys = n_keys;
  for (int i = 0; i < n_keys; i++)
    {
      vcdp_normalise_key (session, &key, i);
      vcdp_ip4_key_encode (session->key[i].context_id, &key, &mp->keys[i]);
    }
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_vcdp_tcp_session_dump_t_handler (vl_api_vcdp_tcp_session_dump_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tcp_check_main_t *tcp = &vcdp_tcp;
  vcdp_per_thread_data_t *ptd;
  vcdp_tcp_check_per_thread_data_t *vptd;
  vcdp_session_t *session;
  vcdp_tcp_check_session_state_t *tcp_session;
  uword thread_index;
  uword session_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  vec_foreach_index (thread_index, vcdp->per_thread_data)
    {
      ptd = vec_elt_at_index (vcdp->per_thread_data, thread_index);
      vptd = vec_elt_at_index (tcp->ptd, thread_index);
      pool_foreach_index (session_index, ptd->sessions)
	{
	  session = vcdp_session_at_index (ptd, session_index);
	  if (session->proto != IP_PROTOCOL_TCP)
	    continue;
	  tcp_session = vec_elt_at_index (vptd->state, session_index);
	  vcdp_tcp_send_session_details (rp, mp->context, session_index,
					 thread_index, session, tcp_session);
	}
    }
}
#include <vcdp/tcp-check/tcp_check.api.c>
static clib_error_t *
vcdp_tcp_check_plugin_api_hookup (vlib_main_t *vm)
{
  vcdp_tcp_check_main_t *tcp = &vcdp_tcp;
  tcp->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (vcdp_tcp_check_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */