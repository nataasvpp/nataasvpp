// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vcdp/service.h>
#include <vcdp/timer_lru.h>

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
      direction = VCDP_SERVICE_CHAIN_FORWARD;
    else if (unformat(line_input, "reverse"))
      direction = VCDP_SERVICE_CHAIN_REVERSE;
    else if (unformat(line_input, "miss"))
      direction = VCDP_SERVICE_CHAIN_MISS;
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
    if (0)
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

  err = vcdp_set_timeout(vcdp, timeout_idx, timeout_val);
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
  u8 *s = 0;

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
    vlib_cli_output(vm, "session id         tenant  index  type proto        state TTL(s)");
    pool_foreach (session, ptd->sessions) {
      tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
      if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
        continue;

      f64 remaining_time = vcdp_session_remaining_time(session, now);
      if (session->state == VCDP_SESSION_STATE_STATIC)
        remaining_time = 0;

      u64 session_net = clib_host_to_net_u64(session->session_id);
      if (detail) {
        vlib_cli_output(vm, "%U\n", format_vcdp_session_detail, ptd, session - ptd->sessions, now);
      } else {
        // if (session->state == VCDP_SESSION_STATE_STATIC)
        //   vlib_cli_output(vm, "0x%U %6d %6d %5U %5U %10U %6s", format_hex_bytes, &session_net, sizeof(session_net),
        //                   tenant->tenant_id, session - ptd->sessions, format_vcdp_session_type, session->type,
        //                   format_ip_protocol, session->proto, format_vcdp_session_state, session->state, "-");

        u8 proto = session->proto;
        s = format(0, "0x%U %6d %6d %5U %5U %12U %6f %U", format_hex_bytes, &session_net, sizeof(session_net),
                       tenant->tenant_id, session - ptd->sessions, format_vcdp_session_type, session->type,
                       format_ip_protocol, proto, format_vcdp_session_state, session->state, remaining_time,
                       format_vcdp_session_key, &session->keys[VCDP_SESSION_KEY_PRIMARY]);
        if (session->key_flags & (VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4 | VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6))
          s = format(s, " %U", format_vcdp_session_key, &session->keys[VCDP_SESSION_KEY_SECONDARY]);

        vlib_cli_output(vm, "%s", s);
        vec_reset_length(s);
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
vcdp_show_interface_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;
  gw_main_t *gm = &gateway_main;
  u32 sw_if_index;
  u32 inside_tenant_id, outside_tenant_id = ~0;
  vec_foreach_index (sw_if_index, gm->tenant_idx_by_sw_if_idx[VLIB_RX]) {
    // vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
    if (sw_if_index == ~0)
      continue;
    u16 *config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_RX], sw_if_index);
    if (config[0] == 0xFFFF)
      continue;
    inside_tenant_id = vcdp_tenant_at_index(vcdp, config[0])->tenant_id;

    if (sw_if_index <= vec_len(gm->tenant_idx_by_sw_if_idx[VLIB_TX])) {
      config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_TX], sw_if_index);
      if (config[0] != 0xFFFF)
        outside_tenant_id = vcdp_tenant_at_index(vcdp, config[0])->tenant_id;
    }

    vlib_cli_output(vm, "%U: tenant: rx %d tx: %d", format_vnet_sw_if_index_name, vnet_get_main(),
                    sw_if_index, inside_tenant_id, outside_tenant_id);

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

VLIB_CLI_COMMAND(show_vcdp_interface, static) = {
  .path = "show vcdp interface",
  .short_help = "show vcdp interface",
  .function = vcdp_show_interface_command_fn,
};

VLIB_CLI_COMMAND(clear_vcdp_sessions, static) = {
  .path = "clear vcdp sessions",
  .short_help = "clear vcdp serssions",
  .function = vcdp_clear_sessions_command_fn,
};

VLIB_CLI_COMMAND(vcdp_set_timeout_command, static) = {.path = "set vcdp timeout",
                                                      .short_help = "set vcdp timeout"
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
  u32 context_id = 0; // TODO: support context_id

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

  vcdp_session_key_t k;
  if (src.version ==  AF_IP6) {
    k.ip6.context_id = context_id;
    k.ip6.src = src.ip.ip6;
    k.ip6.dst = dst.ip.ip6;
    k.ip6.sport = clib_host_to_net_u16(sport);
    k.ip6.dport = clib_host_to_net_u16(dport);
    k.ip6.proto = proto;
    k.is_ip6 = true;
  } else {
    k.ip4.context_id = context_id;
    k.ip4.src = src.ip.ip4.as_u32;
    k.ip4.dst = dst.ip.ip4.as_u32;
    k.ip4.sport = clib_host_to_net_u16(sport);
    k.ip4.dport = clib_host_to_net_u16(dport);
    k.ip4.proto = proto;
    k.is_ip6 = false;
  }

  u16 tenant_idx = vcdp_tenant_idx_by_id(tenant_id);
  if (tenant_idx == ~0) {
    error = clib_error_return(0, "Tenant not found");
    goto done;
  }
  u32 flow_index;
  vcdp_session_t *session = vcdp_create_session(tenant_idx, &k, 0, true, &flow_index);
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

u8 *
format_vcdp_lru_entry(u8 *s, va_list *args)
{
  dlist_elt_t *lru_entry = va_arg(*args, dlist_elt_t *);
  vcdp_per_thread_data_t *ptd = va_arg(*args, vcdp_per_thread_data_t *);

  u32 session_index = lru_entry->value;
  vcdp_session_t *session = vcdp_session_at_index_check(ptd, session_index);
  if (session) {
    s = format(s, "%d %.2f", session_index, session->last_heard);
  } else {
    s = format(s, "No sessions");
  }
  return s;
}

static clib_error_t *
vcdp_show_lru_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  u32 thread_index;

  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    vlib_cli_output(vm, "Elements in LRU list %d", pool_elts(ptd->lru_pool));
    for (int i = 0; i < VCDP_N_TIMEOUT; i++) {
      vlib_cli_output(vm, "Head index: %d", ptd->lru_head_index[i]);
      dlist_elt_t *lru_entry = pool_elt_at_index(ptd->lru_pool, ptd->lru_head_index[i]);
      while (lru_entry) {
        vlib_cli_output(vm, "LRU: %U %d %d %d", format_vcdp_lru_entry, lru_entry, ptd,
        lru_entry->next, lru_entry->prev, lru_entry->value);
        if (lru_entry->next == ~0 || lru_entry->next == ptd->lru_head_index[i])
          break;
        lru_entry = pool_elt_at_index(ptd->lru_pool, lru_entry->next);
      }
    }
  }
  return 0;
}


VLIB_CLI_COMMAND(show_vcdp_lru, static) = {
  .path = "show vcdp lru",
  .short_help = "show vcdp lru",
  .function = vcdp_show_lru_command_fn,
};

#if 0
static int
vcdp_session_table_walk_ip6_cb (clib_bihash_kv_40_8_t *kvp, void *arg)
{
  clib_warning("vcdp_session_table_walk_ip6_cb %llx", kvp->value);

  vcdp_session_ip6_key_t *k = (vcdp_session_ip6_key_t *)&kvp->key;
  clib_warning("KEY %U", format_vcdp_session_ip6_key, k);
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
test_vcdp_session_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 dport, sport;
  ip_address_t src, dst;
  u8 proto;
  u32 tenant_id = ~0;
  u32 context_id = 0; // TODO: support context_id

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d %U:%d %U %U:%d", &tenant_id, unformat_ip_address, &src, &sport,
                 unformat_ip_protocol, &proto, unformat_ip_address, &dst, &dport)) {
    } else if (unformat(line_input, "tenant %d [%U]:%d %U [%U]:%d", &tenant_id, unformat_ip_address, &src, &sport,
                        unformat_ip_protocol, &proto, unformat_ip_address, &dst, &dport)) {
    } else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error, line_input);
      goto done;
    }
  }

  if (sport == 0 || sport > 65535) {
    error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
    goto done;
  }
  if (dport == 0 || dport > 65535) {
    error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
    goto done;
  }

  if (tenant_id == ~0) {
    error = clib_error_return(0, "Specify tenant");
    goto done;
  }

  bool is_ip6 = src.version == AF_IP6;
  vcdp_session_key_t k;
  if (is_ip6) {
    k.ip6.context_id = context_id;
    k.ip6.src = src.ip.ip6;
    k.ip6.dst = dst.ip.ip6;
    k.ip6.sport = clib_host_to_net_u16(sport);
    k.ip6.dport = clib_host_to_net_u16(dport);
    k.ip6.proto = proto;
    k.is_ip6 = true;
  } else {
    k.ip4.context_id = context_id;
    k.ip4.src = src.ip.ip4.as_u32;
    k.ip4.dst = dst.ip.ip4.as_u32;
    k.ip4.sport = clib_host_to_net_u16(sport);
    k.ip4.dport = clib_host_to_net_u16(dport);
    k.ip4.proto = proto;
    k.is_ip6 = false;
  }

  clib_warning("Adding a session");
  u16 tenant_idx = vcdp_tenant_idx_by_id(tenant_id);
  u32 flow_index;
  vcdp_session_t *session = vcdp_create_session(tenant_idx, &k, 0, true, &flow_index);
  if (!session)
    error = clib_error_return(0, "Creating static session failed");
  session->type = is_ip6 ? VCDP_SESSION_TYPE_IP6 : VCDP_SESSION_TYPE_IP4;

  u64 v;
  int rv = vcdp_lookup(&k, is_ip6, &v);
  clib_warning("Looking up the same session %d %llx", rv, v);

  clib_bihash_kv_40_8_t kv;
  kv.key[0] = k.ip6.as_u64[0];
  kv.key[1] = k.ip6.as_u64[1];
  kv.key[2] = k.ip6.as_u64[2];
  kv.key[3] = k.ip6.as_u64[3];
  kv.key[4] = k.ip6.as_u64[4];
  kv.value = 123;

  vcdp_main_t *vcdp = &vcdp_main;


  kv.value = 0x12345678;
  rv = clib_bihash_add_del_40_8(&vcdp->table6, &kv, 2);
  clib_warning("adding key to table %d", rv);

  clib_bihash_kv_40_8_t kv2 = {0};
  rv = clib_bihash_search_40_8(&vcdp_main.table6, &kv, &kv2);
  clib_warning("Looking up the same session %d %llx", rv, kv2.value);


  clib_bihash_foreach_key_value_pair_40_8 (&vcdp->table6, vcdp_session_table_walk_ip6_cb, 0);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(test_vcdp_session_command, static) = {
  .path = "test vcdp session",
  .short_help = "test vcdp session",
  .function = test_vcdp_session_command_fn,
};
#endif