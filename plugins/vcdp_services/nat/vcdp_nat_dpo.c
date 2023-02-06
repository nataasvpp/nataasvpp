// Copyright(c) 2023 Cisco Systems, Inc.

#include <vnet/ip/ip.h>
#include "vcdp_nat_dpo.h"

dpo_type_t vcdp_nat_dpo_type;

void
vcdp_nat_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t *dpo)
{
  dpo_set (dpo, vcdp_nat_dpo_type, dproto, aftr_index);
}

u8 *
format_vcdp_nat_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "VCDP NAT:%d", index));
}

static void
vcdp_nat_dpo_lock (dpo_id_t *dpo)
{
}

static void
vcdp_nat_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t vcdp_nat_dpo_vft = {
  .dv_lock = vcdp_nat_dpo_lock,
  .dv_unlock = vcdp_nat_dpo_unlock,
  .dv_format = format_vcdp_nat_dpo,
};

const static char *const vcdp_nat_ip4_nodes[] = {
  "vcdp-input",
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
}
