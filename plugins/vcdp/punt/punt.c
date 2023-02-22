#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp.h>

#include "punt.h"

vcdp_punt_main_t vcdp_punt_main;

extern vlib_node_registration_t vcdp_punt_input_node;

static clib_error_t *
set_vcdp_punt_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip_address_t src, dst;
  vcdp_punt_main_t *pm = &vcdp_punt_main;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "src %U dst %U", unformat_ip_address, &src,
                 unformat_ip_address, &dst)) {
    } else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error, line_input);
      goto done;
    }
  }

  pm->src.as_u32 = src.ip.ip4.as_u32;
  pm->dst.as_u32 = dst.ip.ip4.as_u32;

  udp_register_dst_port(vm, 33434, vcdp_punt_input_node.index, 1 /* is_ip4*/);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(set_vcdp_punt_command, static) = {
    .path = "set vcdp punt",
    .short_help = "set vcdp punt src <ipaddr> dst <ipaddr>",
    .function = set_vcdp_punt_command_fn,
};