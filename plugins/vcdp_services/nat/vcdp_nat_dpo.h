// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#ifndef included_vcdp_nat_dpo_h
#define included_vcdp_nat_dpo_h

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/drop_dpo.h>

extern dpo_type_t vcdp_nat_dpo_type;
extern dpo_type_t vcdp_nat_if_dpo_type;
void vcdp_nat_dpo_create (dpo_proto_t dproto, u32 natindex, dpo_id_t *dpo, bool is_if);

u8 *format_vcdp_nat_dpo (u8 *s, va_list *args);

void vcdp_nat_dpo_module_init (void);

#endif
