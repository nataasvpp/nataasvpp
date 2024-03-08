// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Get packets from a FIB DPO into VCDP.

#include <vnet/ip/ip.h>
// #include "vcdp_dpo.h"
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>


dpo_type_t vcdp_dpo_type;
dpo_type_t vcdp_if_dpo_type;
fib_source_t fib_src;

void
vcdp_dpo_create (dpo_proto_t dproto, u32 index, dpo_id_t *dpo)
{
    dpo_set (dpo, vcdp_dpo_type, dproto, index);
}

u8 *
format_vcdp_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "dpo-vcdp: %d", index));
}

static void
vcdp_dpo_lock (dpo_id_t *dpo)
{
}

static void
vcdp_dpo_unlock (dpo_id_t *dpo)
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
const static dpo_vft_t vcdp_dpo_vft = {
  .dv_lock = vcdp_dpo_lock,
  .dv_unlock = vcdp_dpo_unlock,
  .dv_format = format_vcdp_dpo,
  // .dv_mk_interpose = vcdp_nat_dpo_interpose,
};

const static char *const vcdp_ip6_nodes[] = {
  "vcdp-lookup-ip6",
  NULL,
};

const static char *const vcdp_ip4_nodes[] = {
  "vcdp-lookup-ip4",
  NULL,
};

const static char *const *const vcdp_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = vcdp_ip4_nodes,
  [DPO_PROTO_IP6] = vcdp_ip6_nodes,
  [DPO_PROTO_MPLS] = 0,
};

clib_error_t *
vcdp_dpo_module_init (vlib_main_t *vm)
{
  vcdp_dpo_type = dpo_register_new_type (&vcdp_dpo_vft, vcdp_nodes);
//   vcdp_if_dpo_type = dpo_register_new_type (&vcdp_dpo_vft, vcdp_nodes);
  fib_src = fib_source_allocate("dpo-vcdp-source", 0x2, FIB_SOURCE_BH_SIMPLE);
  return 0;
}

void
vcdp_dpo_entry(ip_prefix_t *prefix, u16 index)
{
  // Create DPO for the pool
  if (prefix->addr.version == AF_IP6) {
    dpo_id_t dpo_v6 = DPO_INVALID;
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP6,
      .fp_len = prefix->len,
      .fp_addr.ip6.as_u64[0] = prefix->addr.ip.as_u64[0],
      .fp_addr.ip6.as_u64[1] = prefix->addr.ip.as_u64[1],
    };
    vcdp_dpo_create(DPO_PROTO_IP6, index, &dpo_v6);
    u32 fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
    fib_flags |= FIB_ENTRY_FLAG_EXCLUSIVE;
    fib_table_entry_special_dpo_add(0, &pfx, fib_src, fib_flags, &dpo_v6);
    dpo_reset(&dpo_v6);
  } else {
    dpo_id_t dpo_v4 = DPO_INVALID;
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_len = prefix->len,
      .fp_addr.ip4.as_u32 = prefix->addr.ip.ip4.as_u32,
    };
    vcdp_dpo_create(DPO_PROTO_IP6, index, &dpo_v4);
    u32 fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
    fib_flags |= FIB_ENTRY_FLAG_EXCLUSIVE;
    fib_table_entry_special_dpo_add(0, &pfx, fib_src, fib_flags, &dpo_v4);
    dpo_reset(&dpo_v4);
  }
}

VLIB_INIT_FUNCTION(vcdp_dpo_module_init);