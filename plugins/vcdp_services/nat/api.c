// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <vcdp_services/nat/nat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vcdp_services/nat/nat.api_enum.h>
#include <vcdp_services/nat/nat.api_types.h>

#define REPLY_MSG_ID_BASE nat->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_nat_add_t_handler(vl_api_vcdp_nat_add_t *mp)
{
  vl_api_vcdp_nat_add_reply_t *rmp;
  ip4_address_t *addrs = 0;
  nat_main_t *nat = &nat_main;

  vec_resize(addrs, mp->n_addr);
  for (int i = 0; i < mp->n_addr; i++)
    ip4_address_decode(mp->addr[i], addrs + i);
  int rv = vcdp_nat_add((char *)mp->nat_id, addrs, false);
  vec_free(addrs);
  REPLY_MACRO_END(VL_API_VCDP_NAT_ADD_REPLY);
}

static void
vl_api_vcdp_nat_if_add_t_handler(vl_api_vcdp_nat_if_add_t *mp)
{
  vl_api_vcdp_nat_if_add_reply_t *rmp;
  nat_main_t *nat = &nat_main;
  int rv = 0;
  VALIDATE_SW_IF_INDEX_END(mp);
  rv = vcdp_nat_if_add((char *)mp->nat_id, mp->sw_if_index);
  bad_sw_if_index:
  REPLY_MACRO_END(VL_API_VCDP_NAT_IF_ADD_REPLY);
}

static void
vl_api_vcdp_nat_remove_t_handler(vl_api_vcdp_nat_remove_t *mp)
{
  vl_api_vcdp_nat_remove_reply_t *rmp;
  nat_main_t *nat = &nat_main;
  int rv = vcdp_nat_remove((char *)mp->nat_id);
  REPLY_MACRO_END(VL_API_VCDP_NAT_REMOVE_REPLY);
}

static void
vl_api_vcdp_nat_bind_set_unset_t_handler(vl_api_vcdp_nat_bind_set_unset_t *mp)
{
  nat_main_t *nat = &nat_main;
  vl_api_vcdp_nat_bind_set_unset_reply_t *rmp;
  int rv = vcdp_nat_bind_set_unset(mp->tenant_id, (char *)mp->nat_id, mp->is_set);
  REPLY_MACRO_END(VL_API_VCDP_NAT_BIND_SET_UNSET_REPLY);
}

#include <vcdp_services/nat/nat.api.c>
static clib_error_t *
vcdp_nat_api_hookup(vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  nat->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_nat_api_hookup);
