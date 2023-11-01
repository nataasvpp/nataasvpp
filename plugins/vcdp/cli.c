// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vcdp/service.h>

static clib_error_t *
vcdp_tenant_add_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = ~0;
  u32 context_id = ~0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%d", &tenant_id))
      ;
    else if (unformat(line_input, "context %d", &context_id))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (tenant_id == ~0) {
    err = clib_error_return(0, "missing tenant id");
    goto done;
  }
  if (context_id == ~0)
    context_id = tenant_id;
  err = vcdp_tenant_add_del(vcdp, tenant_id, context_id, ~0, true);
done:
  unformat_free(line_input);
  return err;
}

static clib_error_t *
vcdp_set_services_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = ~0;
  u32 bitmap = 0;
  u8 direction = ~0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d", &tenant_id))
      ;
    else if (unformat_user(line_input, unformat_vcdp_service_bitmap, &bitmap))
      ;
    else if (unformat(line_input, "forward"))
      direction = VCDP_FLOW_FORWARD;
    else if (unformat(line_input, "reverse"))
      direction = VCDP_FLOW_REVERSE;
    else if (unformat(line_input, "miss"))
      direction = VCDP_FLOW_MISS;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (tenant_id == ~0) {
    err = clib_error_return(0, "missing tenant id");
    goto done;
  }
  if (direction == (u8) ~0) {
    err = clib_error_return(0, "missing service-chain name");
    goto done;
  }
  err = vcdp_set_services(vcdp, tenant_id, bitmap, direction);
done:
  unformat_free(line_input);
  return err;
}

static clib_error_t *
vcdp_set_timeout_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = ~0;
  u32 timeout_idx = ~0;
  u32 timeout_val = ~0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d", &tenant_id))
      ;
#define _(x, y, z) else if (unformat(line_input, z " %d", &timeout_val)) timeout_idx = VCDP_TIMEOUT_##x;
    foreach_vcdp_timeout
#undef _
      else
    {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (tenant_id == ~0) {
    err = clib_error_return(0, "missing tenant id");
    goto done;
  }
  if (timeout_idx == ~0) {
    err = clib_error_return(0, "missing timeout");
    goto done;
  }

  err = vcdp_set_timeout(vcdp, tenant_id, timeout_idx, timeout_val);
done:
  unformat_free(line_input);
  return err;
}

static clib_error_t *
vcdp_show_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  vcdp_session_t *session;
  vcdp_tenant_t *tenant;
  u32 thread_index = ~0;
  u32 tenant_id = ~0;
  f64 now = vlib_time_now(vm);
  clib_bihash_kv_8_8_t kv = {0};
  u32 session_index;
  u64 session_id;
  bool session_id_set = false, detail = false;
  u32 session_idx = ~0;

  if (unformat_user(input, unformat_line_input, line_input)) {
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(line_input, "tenant %d", &tenant_id))
        ;
      else if (unformat(line_input, "0x%X", sizeof(session_id), &session_id)) {
        session_id_set = true;
      } else if (unformat(line_input, "%u", &session_idx)) {
        ;
      } else if (unformat(line_input, "thread %u", &thread_index)) {
        ;
      } else if (unformat(line_input, "detail")) {
        detail = true;
      } else {
        err = unformat_parse_error(line_input);
        break;
      }
    }
    unformat_free(line_input);
  }

  if (err)
    return err;

  if (session_idx != ~0) {
    if (thread_index == ~0 || thread_index >= vec_len(vcdp->per_thread_data))
      return clib_error_return(0, "Thread index not set");
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    vcdp_session_t *session = vcdp_session_at_index_check(ptd, session_idx);
    if (session)
      vlib_cli_output(vm, "%U", format_vcdp_session_detail, ptd, session_idx, now);
    else
      err = clib_error_return(0, "Session index %u not found", session_idx);
    return err;
  }
  if (session_id_set) {
    kv.key = session_id;
    if (!clib_bihash_search_inline_8_8(&vcdp->session_index_by_id, &kv)) {
      thread_index = vcdp_thread_index_from_lookup(kv.value);
      session_index = vcdp_session_index_from_lookup(kv.value);
      ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
      vlib_cli_output(vm, "%U", format_vcdp_session_detail, ptd, session_index, now);
    } else {
      err = clib_error_return(0, "Session id 0x%llx not found", session_id);
    }
    return err;
  }

  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    if (vec_len(vcdp->per_thread_data) > 1)
      vlib_cli_output(vm, "Thread #%d:", thread_index);
    vlib_cli_output(vm, "session id         tenant  index type proto      state TTL(s)");
    pool_foreach (session, ptd->sessions) {
      tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
      if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
        continue;

      f64 remaining_time = session->timer.next_expiration - now;
      if (session->state == VCDP_SESSION_STATE_STATIC)
        remaining_time = 0;

      u64 session_net = clib_host_to_net_u64(session->session_id);
      vcdp_session_ip4_key_t *k1, *k2;
      if (detail) {
        vlib_cli_output(vm, "%U", format_vcdp_session_detail, ptd, session - ptd->sessions, now);
      } else {
        if (session->state == VCDP_SESSION_STATE_STATIC)
          vlib_cli_output(vm, "0x%U %6d %6d %4U %5U %10U %6s", format_hex_bytes, &session_net, sizeof(session_net),
                          tenant->tenant_id, session - ptd->sessions, format_vcdp_session_type, session->type,
                          format_ip_protocol, session->proto, format_vcdp_session_state, session->state, "-");
        else
          vlib_cli_output(vm, "0x%U %6d %6d %4U %5U %10U %6f", format_hex_bytes, &session_net, sizeof(session_net),
                          tenant->tenant_id, session - ptd->sessions, format_vcdp_session_type, session->type,
                          format_ip_protocol, session->proto, format_vcdp_session_state, session->state, remaining_time);

        k1 = &session->keys[VCDP_SESSION_KEY_PRIMARY];
        k2 = &session->keys[VCDP_SESSION_KEY_SECONDARY];
        vlib_cli_output(vm, "%4d %15U:%u -> %15U:%u", k1->context_id, format_ip4_address, &k1->src,
                        clib_net_to_host_u16(k1->sport), format_ip4_address, &k1->dst, clib_net_to_host_u16(k1->dport));
        vlib_cli_output(vm, "%4d %15U:%u -> %15U:%u", k2->context_id, format_ip4_address, &k2->src,
                        clib_net_to_host_u16(k2->sport), format_ip4_address, &k2->dst, clib_net_to_host_u16(k2->dport));
      }
    }
  }
  return err;
}

static clib_error_t *
vcdp_show_summary_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  u32 thread_index;
  // u32 n_threads = vlib_num_workers();

  vlib_cli_output(vm, "Configuration:");
  vlib_cli_output(vm, "Max Tenants: %d", vcdp_cfg_main.no_tenants);
  vlib_cli_output(vm, "Max Sessions per thread: %d", vcdp_cfg_main.no_sessions_per_thread);
  vlib_cli_output(vm, "Max NAT instances: %d", vcdp_cfg_main.no_nat_instances);
  vlib_cli_output(vm, "Max Tunnels: %d", vcdp_cfg_main.no_tunnels);

  vlib_cli_output(vm, "Threads: %d", vec_len(vcdp->per_thread_data));
  vlib_cli_output(vm, "Active tenants: %d", pool_elts(vcdp->tenants));

  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    vlib_cli_output(vm, "Active sessions (%d): %d", thread_index, pool_elts(ptd->sessions));
    vlib_cli_output(vm, "Expired vector length: %d", vec_len(ptd->expired_sessions));
  }
  vcdp_tenant_t *tenant;
  pool_foreach(tenant, vcdp->tenants) {
    u32 idx = vcdp->tenants - tenant;

    if (idx >= vlib_simple_counter_n_counters(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED]))
      break;

    counter_t created = vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], idx);
    counter_t removed = vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], idx);
    counter_t reused = vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REUSED], idx);
    vlib_cli_output(vm, "Tenant: %d created %ld expired %ld reused %ld", idx, created, removed, reused);
  }

  return 0;
}

static clib_error_t *
vcdp_clear_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_session_clear();
  return 0;
}

static clib_error_t *
vcdp_show_tenant_detail_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tenant_t *tenant;
  u32 tenant_id = ~0;
  u16 tenant_idx;
  u8 detail = 0;
  if (unformat_user(input, unformat_line_input, line_input)) {
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(line_input, "%d detail", &tenant_id))
        detail = 1;
      else if (unformat(line_input, "%d", &tenant_id))
        ;
      else {
        err = unformat_parse_error(line_input);
        break;
      }
    }
    unformat_free(line_input);
  }
  if (err)
    return err;

  pool_foreach_index (tenant_idx, vcdp->tenants) {
    tenant = vcdp_tenant_at_index(vcdp, tenant_idx);

    if (tenant_id != ~0 && tenant->tenant_id != tenant_id)
      continue;

    vlib_cli_output(vm, "Tenant %d", tenant->tenant_id);
    vlib_cli_output(vm, "  %U", format_vcdp_tenant, vcdp, tenant_idx, tenant);
    if (detail)
      vlib_cli_output(vm, "  %U", format_vcdp_tenant_extra, vcdp, tenant_idx, tenant);
  }

  return err;
}

VLIB_CLI_COMMAND(vcdp_tenant_add_del_command, static) = {
  .path = "set vcdp tenant",
  .short_help = "set vcdp tenant <tenant-id> context <context-id> [<flags>]",
  .function = vcdp_tenant_add_command_fn,
};

VLIB_CLI_COMMAND(vcdp_set_services_command, static) = {
  .path = "set vcdp services",
  .short_help = "set vcdp services tenant <tenant-id>"
                " [SERVICE_NAME]+ <forward|reverse|miss>",
  .function = vcdp_set_services_command_fn,
};

VLIB_CLI_COMMAND(show_vcdp_sessions_command, static) = {
  .path = "show vcdp session",
  .short_help = "show vcdp session [session index] [thread <n>] [tenant <tenant-id>] [0x<session-id>] [detail]",
  .function = vcdp_show_sessions_command_fn,
};

VLIB_CLI_COMMAND(show_vcdp_tenant, static) = {
  .path = "show vcdp tenant",
  .short_help = "show vcdp tenant [<tenant-id> [detail]]",
  .function = vcdp_show_tenant_detail_command_fn,
};

VLIB_CLI_COMMAND(show_vcdp_summary, static) = {
  .path = "show vcdp summary",
  .short_help = "show vcdp summary",
  .function = vcdp_show_summary_command_fn,
};

VLIB_CLI_COMMAND(clear_vcdp_sessions, static) = {
  .path = "clear vcdp sessions",
  .short_help = "clear vcdp serssions",
  .function = vcdp_clear_sessions_command_fn,
};

VLIB_CLI_COMMAND(vcdp_set_timeout_command, static) = {.path = "set vcdp timeout",
                                                      .short_help = "set vcdp timeout tenant <tenant-id>"
                                                                    " <timeout-name> <timeout-value>",
                                                      .function = vcdp_set_timeout_command_fn};

/*
 * Display the set of available services.
 */
static clib_error_t *
vcdp_show_services_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_service_main_t *sm = &vcdp_service_main;
  vcdp_service_registration_t **services = sm->services;
  vcdp_service_registration_t *service;
  char **p;
  vlib_cli_output(vm, "Available services:");

  for (uword i = 0; i < vec_len(services); i++) {
    service = vec_elt_at_index(services, i)[0];
    vlib_cli_output(vm, "  %s%s", service->node_name, service->is_terminal ? " (terminal)" : "");
    p = service->runs_before;
    while (*p) {
      vlib_cli_output(vm, "     %s (before)", *p);
      p++;
    }
    p = service->runs_after;
    while (*p) {
      vlib_cli_output(vm, "     %s (after)", *p);
      p++;
    }
  }
  return 0;
}

VLIB_CLI_COMMAND(vcdp_show_services_command, static) = {
  .path = "show vcdp services",
  .short_help = "show vcdp services [verbose]",
  .function = vcdp_show_services_command_fn,
};

static clib_error_t *
set_vcdp_session_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 dport, sport;
  ip_address_t src, dst;
  u8 proto;
  u32 tenant_id = ~0;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d %U:%d %U %U:%d", &tenant_id, unformat_ip_address, &src, &sport,
                 unformat_ip_protocol, &proto, unformat_ip_address, &dst, &dport)) {
      if (sport == 0 || sport > 65535) {
        error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
        goto done;
      }
      if (dport == 0 || dport > 65535) {
        error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
        goto done;
      }
    } else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error, line_input);
      goto done;
    }
  }

  if (tenant_id == ~0) {
    error = clib_error_return(0, "Specify tenant");
    goto done;
  }

  vcdp_session_ip4_key_t k = {
    .context_id = 0,
    .src = src.ip.ip4.as_u32,
    .dst = dst.ip.ip4.as_u32,
    .sport = clib_host_to_net_u16(sport),
    .dport = clib_host_to_net_u16(dport),
    .proto = proto,
  };

  u16 tenant_idx = vcdp_tenant_idx_by_id(tenant_id);
  u32 flow_index;
  vcdp_session_t *session = vcdp_create_session_v4(tenant_idx, &k, 0, true, &flow_index);
  if (!session)
    error = clib_error_return(0, "Creating static session failed");

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(set_vcdp_session_command, static) = {
  .path = "set vcdp session",
  .short_help = "set vcdp session tenant <tenant> <ipaddr:port> <protocol> <ipaddr:port>",
  .function = set_vcdp_session_command_fn,
};
