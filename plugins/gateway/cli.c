// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include "tunnel/tunnel.h"

/*
 *  set vcdp gateway interface <interface> tenant <tenant-id>
 */
static clib_error_t *
gateway_interface_input_enable_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 sw_if_index = ~0, tenant_id = ~0;
  bool output_arc = false;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else if (unformat(line_input, "output"))
      output_arc = true;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (sw_if_index == ~0 || tenant_id == ~0) {
    err = clib_error_return(0, "missing arguments");
    goto done;
  }
  int rv = gw_interface_input_enable_disable(sw_if_index, tenant_id, output_arc, true);
  if (rv != 0) {
    err = clib_error_return(0, "could not enable interface");
  }

done:
  unformat_free(line_input);
  return err;
}

VLIB_CLI_COMMAND(gateway_interface_input_enable_command, static) = {
  .path = "set vcdp gateway interface",
  .short_help = "set vcdp gateway interface <interface> tenant <tenant-id> [output]",
  .function = gateway_interface_input_enable_command_fn,
};

/*
 *  set vcdp gateway prefix <prefix> tenant <tenant-id>
 */
static clib_error_t *
gateway_prefix_input_enable_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 tenant_id = ~0;
  ip_prefix_t pfx = {0};

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%U", unformat_ip_prefix, &pfx))
      ;
    else if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (tenant_id == ~0) {
    err = clib_error_return(0, "missing arguments");
    goto done;
  }
  int rv = gw_prefix_input_enable_disable(&pfx, tenant_id, true);
  if (rv != 0) {
    err = clib_error_return(0, "could not enable prefix dpo");
  }

done:
  unformat_free(line_input);
  return err;
}

VLIB_CLI_COMMAND(gateway_prefix_input_enable_command, static) = {
  .path = "set vcdp gateway prefix",
  .short_help = "set vcdp gateway prefix <prefix> tenant <tenant-id>",
  .function = gateway_prefix_input_enable_command_fn,
};

/*
 *  set vcdp gateway tunnel <ifname>
 */
static clib_error_t *
vcdp_tunnel_enable_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 sw_if_index;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  if (sw_if_index == ~0) {
    err = clib_error_return(0, "valid interface name required");
    goto done;
  }
  vcdp_tunnel_enable_disable_input(sw_if_index, true);

done:
  unformat_free(line_input);
  return err;
}

/*
 * Attach tunnel decap processing to an interface.
 */
VLIB_CLI_COMMAND(vcdp_tunnel_enable_command, static) = {
  .path = "set vcdp gateway tunnel",
  .short_help = "set vcdp gateway tunnel <ifname>",
  .function = vcdp_tunnel_enable_command_fn,
};

static uword
unformat_vcdp_tunnel_method(unformat_input_t *input, va_list *args)
{
  vcdp_tunnel_method_t *m = va_arg(*args, vcdp_tunnel_method_t *);
  if (unformat(input, "vxlan-dummy-l2"))
    *m = VCDP_TUNNEL_VXLAN_DUMMY_L2;
  else if (unformat(input, "geneve-l3"))
    *m = VCDP_TUNNEL_GENEVE_L3;
  else
    return 0;
  return 1;
}

static clib_error_t *
vcdp_tunnel_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 dport = ~0, sport = 0, mtu = 0;
  ip_address_t src = {0}, dst = {0};
  u32 method = ~0;
  u32 tenant_id = ~0;
  char *tunnel_id = 0;
  mac_address_t src_mac = {0};
  mac_address_t dst_mac = {0};

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "src %U", unformat_ip_address, &src))
      ;
    else if (unformat(line_input, "dst %U", unformat_ip_address, &dst))
      ;
    else if (unformat(line_input, "method %U", unformat_vcdp_tunnel_method, &method))
      ;
    else if (unformat(line_input, "sport %d", &sport))
      ;
    else if (unformat(line_input, "dport %d", &dport))
      ;
    else if (unformat(line_input, "mtu %d", &mtu))
      ;
    else if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else if (unformat(line_input, "id %s", &tunnel_id))
      ;
    else if (unformat(line_input, "src-mac %U", unformat_ethernet_address, &src_mac))
      ;
    else if (unformat(line_input, "dst-mac %U", unformat_ethernet_address, &dst_mac))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  int rv = vcdp_tunnel_add(tunnel_id, tenant_id, method, &src, &dst, sport, dport, mtu, &src_mac, &dst_mac);
  if (rv) {
    err = clib_error_return(0, "missing tunnel parameters");
  }

done:
  unformat_free(line_input);
  return err;
}

/*
 * Define a tunnel
 */
VLIB_CLI_COMMAND(vcdp_tunnel_command, static) = {
  .path = "set vcdp tunnel",
  .short_help = "set vcdp tunnel id <id> tenant <tenant-id> method "
                "<geneve-l3|vxlan-dummy-l2|vxlan-gpe> src "
                "<src> dst <dst> [sport <sport>] dport <dport> [mtu <mtu>] [src-mac <mac-address> dst-mac <mac-address>]",
  .function = vcdp_tunnel_command_fn,
};

static clib_error_t *
vcdp_tunnel_show_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  // unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  // vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tunnel_t *tunnel;
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;

  table_t _t = {}, *t = &_t;
  u32 /*n_row = 0, */col = 0;
  table_add_header_row (t, 0);
  table_add_header_col(t, 8, "id", "tenant", "method", "src", "dst", "src mac", "dst mac", "mtu");
  pool_foreach (tunnel, tm->tunnels) {
    table_format_cell(t, col, 0, "%s", tunnel->tunnel_id);
    table_format_cell(t, col, 1, "%d", tunnel->tenant_id);
    table_format_cell(t, col, 2, "%d", tunnel->method);
    table_format_cell(t, col, 3, "%U:%u", format_ip_address, &tunnel->src, tunnel->sport);
    table_format_cell(t, col, 4, "%U:%u", format_ip_address, &tunnel->dst, tunnel->dport);
    table_format_cell(t, col, 5, "%U", format_mac_address, &tunnel->src_mac);
    table_format_cell(t, col, 6, "%U", format_mac_address, &tunnel->dst_mac);
    table_format_cell(t, col, 7, "%d", tunnel->mtu);
    col++;
  }
  vlib_cli_output(vm, "%U", format_table, t);
  table_free(t);

  return err;
}

VLIB_CLI_COMMAND(show_vcdp_tunnels_command, static) = {
  .path = "show vcdp tunnels",
  .short_help = "show vcdp tunnels",
  .function = vcdp_tunnel_show_command_fn,
};
