// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp_services/nat/nat.h>

static clib_error_t *
vcdp_nat_add_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  ip4_address_t tmp;
  ip4_address_t *addr = 0;
  u8 *nat_id = 0;
  u32 tenant_id = ~0;
  u32 sw_if_index = ~0;
  u32 port_retries = ~0;
  u32 context_id = 0;
  int rv;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "id %s", &nat_id))
      ;
    if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else if (unformat(line_input, "context %d", &context_id))
      ;
    else if (unformat(line_input, "%U", unformat_ip4_address, &tmp))
      vec_add1(addr, tmp);
    else if (unformat(line_input, "interface %U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else if (unformat(line_input, "port-retries %d", &port_retries))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  if (tenant_id != ~0 && addr) {
    err = clib_error_return(0, "NAT mapping to tenant failed");
    goto done;
  }

  if (tenant_id != ~0) {
    rv = vcdp_nat_bind_set_unset(tenant_id, (char *) nat_id, true);
  } else if (sw_if_index != ~0) {
    rv = vcdp_nat_if_add((char *) nat_id, sw_if_index);
  } else if (port_retries != ~0) {
    vcdp_nat_set_port_retries(port_retries);
    rv = 0;
  } else {
    rv = vcdp_nat_add((char *) nat_id, context_id, addr, false);
  }
  if (rv != 0) {
    err = clib_error_return(0, "NAT instance command failed");
  }

done:
  unformat_free(line_input);
  vec_free(addr);
  return err;
}

VLIB_CLI_COMMAND(vcdp_nat_add_command, static) = {
  .path = "set vcdp nat",
  .short_help = "[un]set vcdp nat id <id> {<ip-addr>+ | tenant <tenant-id> | interface <interface>}"
                "[port-retries <port-retries>]",
  .function = vcdp_nat_add_command_fn,
};

static clib_error_t *
vcdp_nat_show_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  nat_main_t *nat = &nat_main;
  nat_instance_t *instance;
  u8 *s = 0;
  pool_foreach (instance, nat->instances) {
    vlib_cli_output(vm, "%s:", instance->nat_id);
    for (int i = 0; i < vec_len(instance->addresses); i++) {
      s = format(s, "%U ", format_ip4_address, &instance->addresses[i]);
    }
    vlib_cli_output(vm, "\t%v", s);
    vec_reset_length(s);
  }
  vec_free(s);
  return err;
}

VLIB_CLI_COMMAND(show_vcdp_nat_command, static) = {
  .path = "show vcdp nat",
  .short_help = "show vcdp nat",
  .function = vcdp_nat_show_command_fn,
};

static clib_error_t *
vcdp_nat_show_stats_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  nat_main_t *nat = &nat_main;
  u32 nat_idx;
  pool_foreach_index (nat_idx, nat->instances) {
    vlib_cli_output(vm, "%s:", nat->instances[nat_idx].nat_id);
#define _(NAME, VALUE, STR)                                                                                            \
  vlib_cli_output(vm, "\t%s: %lu", STR, vlib_get_simple_counter(&nat->simple_counters[VALUE], nat_idx));
    foreach_vcdp_nat_simple_counter
#undef _
      vlib_counter_t counter;
#define _(NAME, VALUE, STR)                                                                                            \
  vlib_get_combined_counter(&nat->combined_counters[VALUE], nat_idx, &counter);                                        \
  vlib_cli_output(vm, "\t%s: %lu packets, %lu bytes", STR, counter.packets, counter.bytes);
    foreach_vcdp_nat_combined_counter
#undef _
  }
  return err;
}

VLIB_CLI_COMMAND(show_vcdp_nat_stats_command, static) = {
  .path = "show vcdp nat statistics",
  .short_help = "show vcdp nat statistics",
  .function = vcdp_nat_show_stats_command_fn,
};

/*
 *
 */
static clib_error_t *
vcdp_nat_port_forwarding_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  u8 *nat_id = 0;
  int rv;
  u32 dport, sport;
  u32 tenant_id = ~0;
  ip4_address_t src, dst;
  u8 proto;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "id %s", &nat_id))
      ;
    else if (unformat(line_input, "tenant %u", &tenant_id))
      ;
    else if (unformat(line_input, "%U:%d %U %U:%d", unformat_ip4_address, &src, &sport, unformat_ip_protocol, &proto,
                      unformat_ip4_address, &dst, &dport))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  if (tenant_id == ~0 || nat_id == 0) {
    err = clib_error_return(0, "NAT instance command failed");
    goto done;
  }

  rv = vcdp_nat_port_forwarding((char *) nat_id, tenant_id, &src, sport, proto, &dst, dport, true);
  if (rv != 0) {
    err = clib_error_return(0, "NAT instance command failed");
  }

done:
  unformat_free(line_input);
  return err;
}

VLIB_CLI_COMMAND(vcdp_nat_port_forwarding_command, static) = {
  .path = "set vcdp nat port-forwarding",
  .short_help = "set vcdp nat port-forwarding id <id> tenant <n> src:sport proto dst:dport",
  .function = vcdp_nat_port_forwarding_command_fn,
};
