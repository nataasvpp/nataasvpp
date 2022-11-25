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
  int rv;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "id %s", &nat_id))
      ;
    if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else if (unformat(line_input, "%U", unformat_ip4_address, &tmp))
      vec_add1(addr, tmp);
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  if (tenant_id != ~0 && addr) {
    err = clib_error_return (0, "NAT mapping to tenant failed");
    goto done;
  }

  if (tenant_id != ~0) {
    rv = vcdp_nat_tenant_to_instance_set_unset(tenant_id, (char *)nat_id, true);
  } else {
    rv = vcdp_nat_add((char *)nat_id, addr);
  }
  if (rv != 0) {
    err = clib_error_return (0, "NAT instance command failed");
  }

done:
  unformat_free(line_input);
  vec_free(addr);
  return err;
}

VLIB_CLI_COMMAND(vcdp_nat_add_command, static) = {
  .path = "set vcdp nat",
  .short_help = "[un]set vcdp nat id <id> {<ip-addr>+ | tenant <tenand-id>}",
  .function = vcdp_nat_add_command_fn,
};
