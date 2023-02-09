// Copyright(c) 2023 Cisco Systems, Inc.

#include <vnet/ip/ip.h>
#include "vcdp_nat_dpo.h"
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>


dpo_type_t vcdp_nat_dpo_type;
dpo_type_t vcdp_nat_if_dpo_type;

void
vcdp_nat_dpo_create (dpo_proto_t dproto, u32 natindex, dpo_id_t *dpo, bool is_if)
{
  if (is_if) {
    dpo_set (dpo, vcdp_nat_if_dpo_type, dproto, natindex);
  } else {
    dpo_set (dpo, vcdp_nat_dpo_type, dproto, natindex);
  }
}

u8 *
format_vcdp_nat_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "dpo-vcdp-nat:%d", index));
}

static void
vcdp_nat_dpo_lock (dpo_id_t *dpo)
{
}

static void
vcdp_nat_dpo_unlock (dpo_id_t *dpo)
{
}
#if 0

static void
vcdp_nat_dpo_interpose(const dpo_id_t *original, const dpo_id_t *parent, dpo_id_t *clone)
{
  clib_warning("interpose called");
  /* stack the clone on the FIB provided parent */
  dpo_id_t parent_id;
  dpo_stack(vcdp_nat_dpo_type, DPO_PROTO_IP4, &parent_id, parent);

  /* return the clone */
  index_t index = 0;
  dpo_set(clone, vcdp_nat_dpo_type, DPO_PROTO_IP4, index);
}
#endif
const static dpo_vft_t vcdp_nat_dpo_vft = {
  .dv_lock = vcdp_nat_dpo_lock,
  .dv_unlock = vcdp_nat_dpo_unlock,
  .dv_format = format_vcdp_nat_dpo,
  // .dv_mk_interpose = vcdp_nat_dpo_interpose,
};

const static char *const vcdp_nat_ip4_nodes[] = {
  "vcdp-lookup-ip4-nocreate",
  NULL,
};

#if 0
const static char *const vcdp_nat_ip6_nodes[] = {
  NULL,
};
#endif

const static char *const *const vcdp_nat_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = vcdp_nat_ip4_nodes,
  [DPO_PROTO_IP6] = 0,
  [DPO_PROTO_MPLS] = 0,
};

void
vcdp_nat_dpo_module_init (void)
{
  vcdp_nat_dpo_type = dpo_register_new_type (&vcdp_nat_dpo_vft, vcdp_nat_nodes);
  vcdp_nat_if_dpo_type = dpo_register_new_type (&vcdp_nat_dpo_vft, vcdp_nat_nodes);
}
