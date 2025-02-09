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
  u32 timeouts[VCDP_N_TIMEOUT] = {0};
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (0)
      ;
#define _(x, y, z) else if (unformat(line_input, z " %d", &timeouts[VCDP_TIMEOUT_##x]));
    foreach_vcdp_timeout
#undef _
      else
    {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  err = vcdp_set_timeout(vcdp, timeouts);
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
    vcdp_session_t *session = vcdp_session_at_index_check(vcdp, session_idx);
    if (session)
      vlib_cli_output(vm, "%U", format_vcdp_session_detail, vcdp, session_idx, now);
    else
      err = clib_error_return(0, "Session index %u not found", session_idx);
    return err;
  }
  if (session_id_set) {
    kv.key = session_id;
    if (!clib_bihash_search_inline_8_8(&vcdp->session_index_by_id, &kv)) {
      thread_index = vcdp_thread_index_from_lookup(kv.value);
      session_index = vcdp_session_index_from_lookup(kv.value);
      vlib_cli_output(vm, "%U", format_vcdp_session_detail, vcdp, session_index, now);
    } else {
      err = clib_error_return(0, "Session id 0x%llx not found", session_id);
    }
    return err;
  }

  vlib_cli_output(vm, "session id         thread tenant  index  type proto        state TTL(s)");
  pool_foreach (session, vcdp->sessions) {
    tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
    if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
      continue;

    f64 remaining_time = vcdp_session_remaining_time(session, now);
    if (remaining_time <= 0 && session->state != VCDP_SESSION_STATE_STATIC)
      continue;
    // if (session->state == VCDP_SESSION_STATE_STATIC)
    //   remaining_time = 0;

    u64 session_net = clib_host_to_net_u64(session->session_id);
    if (detail) {
      vlib_cli_output(vm, "%U\n", format_vcdp_session_detail, vcdp, session - vcdp->sessions, now);
    } else {
      // if (session->state == VCDP_SESSION_STATE_STATIC)
      //   vlib_cli_output(vm, "0x%U %6d %6d %5U %5U %10U %6s", format_hex_bytes, &session_net, sizeof(session_net),
      //                   tenant->tenant_id, session - vcdp->sessions, format_vcdp_session_type, session->type,
      //                   format_ip_protocol, session->proto, format_vcdp_session_state, session->state, "-");

      u8 proto = session->keys[VCDP_SESSION_KEY_PRIMARY].proto;
      s = format(0, "0x%U %6d %6d %6d %5U %5U %12U %6f %U", format_hex_bytes, &session_net, sizeof(session_net),
                 session->thread_index, tenant->tenant_id, session - vcdp->sessions, format_vcdp_session_type, session->type,
                 format_ip_protocol, proto, format_vcdp_session_state, session->state, remaining_time,
                 format_vcdp_session_key, &session->keys[VCDP_SESSION_KEY_PRIMARY]);

      if (session->keys[VCDP_SESSION_KEY_SECONDARY].dst.ip4.as_u32 ||
          session->keys[VCDP_SESSION_KEY_SECONDARY].src.ip4.as_u32)
        s = format(s, " %U", format_vcdp_session_key, &session->keys[VCDP_SESSION_KEY_SECONDARY]);

      vlib_cli_output(vm, "%v", s);
      vec_reset_length(s);
    }
  }
  return err;
}

static clib_error_t *
vcdp_show_summary_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;

  vlib_cli_output(vm, "Configuration:");
  vlib_cli_output(vm, "Max Tenants: %d", vcdp_cfg_main.no_tenants);
  vlib_cli_output(vm, "Max Sessions: %d", vcdp_cfg_main.no_sessions);
  vlib_cli_output(vm, "Max NAT instances: %d", vcdp_cfg_main.no_nat_instances);
  vlib_cli_output(vm, "Max Tunnels: %d", vcdp_cfg_main.no_tunnels);

  vlib_cli_output(vm, "Threads: %d", vec_len(vcdp->per_thread_data));
  vlib_cli_output(vm, "Active tenants: %d", pool_elts(vcdp->tenants));
  vlib_cli_output(vm, "Timers:");

#define _(x, y, z) vlib_cli_output(vm, "  " z ": %d", vcdp->timeouts[VCDP_TIMEOUT_##x]);
  foreach_vcdp_timeout
#undef _

    vlib_cli_output(vm, "Active sessions: %d", pool_elts(vcdp->sessions));
  u32 tenant_idx;
  pool_foreach_index (tenant_idx, vcdp->tenants) {
    vlib_cli_output(vm, "%d: %U", vcdp->tenants[tenant_idx].tenant_id, format_vcdp_tenant_stats, vcdp, tenant_idx);
  }

  return 0;
}

static clib_error_t *
vcdp_show_interface_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;
  gw_main_t *gm = &gateway_main;
  u32 sw_if_index;
  u32 inside_tenant_id, outside_tenant_id;
  vec_foreach_index (sw_if_index, gm->tenant_idx_by_sw_if_idx[VLIB_RX]) {
    // vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
    if (sw_if_index == ~0)
      continue;
    u16 *config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_RX], sw_if_index);
    if (config[0] == 0xFFFF)
      continue;
    inside_tenant_id = vcdp_tenant_at_index(vcdp, config[0])->tenant_id;
    outside_tenant_id = ~0;
    if (sw_if_index < vec_len(gm->tenant_idx_by_sw_if_idx[VLIB_TX])) {
      config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_TX], sw_if_index);
      if (config[0] != 0xFFFF)
        outside_tenant_id = vcdp_tenant_at_index(vcdp, config[0])->tenant_id;
    }

    vlib_cli_output(vm, "%U: tenant: rx %d tx: %d", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index,
                    inside_tenant_id, outside_tenant_id);
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

static clib_error_t *
vcdp_tenant_show_stats_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_idx;
  pool_foreach_index (tenant_idx, vcdp->tenants) {
    vlib_cli_output(vm, "%d: %U", vcdp->tenants[tenant_idx].tenant_id, format_vcdp_tenant_stats, vcdp, tenant_idx);
  }
  return err;
}

VLIB_CLI_COMMAND(show_vcdp_tenant_stats_command, static) = {
  .path = "show vcdp tenant statistics",
  .short_help = "show vcdp tenant statistics",
  .function = vcdp_tenant_show_stats_command_fn,
};

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
  ip46_address_t src, dst;
  u8 proto;
  u32 tenant_id = ~0;
  u32 context_id = 0; // TODO: support context_id

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d %U:%d %U %U:%d", &tenant_id, unformat_ip46_address, &src, IP46_TYPE_ANY, &sport,
                 unformat_ip_protocol, &proto, unformat_ip46_address, &dst, IP46_TYPE_ANY, &dport)) {
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
  k.context_id = context_id;
  k.src = src;
  k.dst = dst;
  k.sport = clib_host_to_net_u16(sport);
  k.dport = clib_host_to_net_u16(dport);
  k.proto = proto;

  u16 tenant_idx = vcdp_tenant_idx_by_id(tenant_id);
  if (tenant_idx == VCDP_TENANT_INVALID_IDX) {
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
  vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);

  u32 session_index = lru_entry->value;
  vcdp_session_t *session = vcdp_session_at_index_check(vcdp, session_index);
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
        vlib_cli_output(vm, "LRU: %U %d %d %d", format_vcdp_lru_entry, lru_entry, vcdp, lru_entry->next,
                        lru_entry->prev, lru_entry->value);
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

#include <vnet/classify/vnet_classify.h>

static void
vcdp_filter_set_trace_chain(vnet_classify_main_t *cm, u32 table_index)
{
  clib_warning("Setting trace chain to %d", table_index);
  // if (table_index == ~0) {
  //   u32 old_table_index;

  //   old_table_index = vlib_global_main.trace_filter.classify_table_index;
  //   vnet_classify_delete_table_index(cm, old_table_index, 1);
  // }
  // vlib_global_main.trace_filter.classify_table_index = table_index;
}

static clib_error_t *
vcdp_set_trace_filter_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 nbuckets = 8;
  uword memory_size = (uword) (128 << 10);
  u32 skip = ~0;
  u32 match = ~0;
  u8 *match_vector;
  int is_add = 1;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 current_data_flag = 0;
  int current_data_offset = 0;
  u8 *mask = 0;
  vnet_classify_main_t *cm = &vnet_classify_main;
  int rv = 0;
  clib_error_t *err = 0;

  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "del"))
      is_add = 0;
    else if (unformat(line_input, "buckets %d", &nbuckets))
      ;
    else if (unformat(line_input, "mask %U", unformat_classify_mask, &mask, &skip, &match))
      ;
    else if (unformat(line_input, "memory-size %U", unformat_memory_size, &memory_size))
      ;
    else
      break;
  }

  if (is_add && mask == 0)
    err = clib_error_return(0, "Mask required");

  else if (is_add && skip == ~0)
    err = clib_error_return(0, "skip count required");

  else if (is_add && match == ~0)
    err = clib_error_return(0, "match count required");

  if (err) {
    unformat_free(line_input);
    return err;
  }

  if (!is_add) {
    /*
     * Delete an existing trace classify table.
     */
    vcdp_filter_set_trace_chain(cm, ~0);

    vec_free(mask);
    unformat_free(line_input);

    return 0;
  }

  /*
   * Find an existing compatible table or else make a new one.
   */
  table_index = vcdp->trace_filter_table_index;
  if (table_index != ~0) {
    /*
     * look for a compatible table in the existing chain
     *  - if a compatible table is found, table_index is updated with it
     *  - if not, table_index is updated to ~0 (aka nil) and because of that
     *    we are going to create one (see below). We save the original head
     *    in next_table_index so we can chain it with the newly created
     *    table
     */
    next_table_index = table_index;
    table_index = classify_lookup_chain(table_index, mask, skip, match);
  }

  /*
   * When no table is found, make one.
   */
  if (table_index == ~0) {
    u32 new_head_index;

    /*
     * Matching table wasn't found, so create a new one at the
     * head of the next_table_index chain.
     */
    rv = vnet_classify_add_del_table(cm, mask, nbuckets, memory_size, skip, match, next_table_index, miss_next_index,
                                     &table_index, current_data_flag, current_data_offset, 1, 0);

    if (rv != 0) {
      vec_free(mask);
      unformat_free(line_input);
      return clib_error_return(0, "vnet_classify_add_del_table returned %d", rv);
    }

    /*
     * Reorder tables such that masks are most-specify to least-specific.
     */
    new_head_index = classify_sort_table_chain(cm, table_index);

    /*
     * Put first classifier table in chain in a place where
     * other data structures expect to find and use it.
     */
    vcdp_filter_set_trace_chain(cm, new_head_index);
  }

  vec_free(mask);

  /*
   * Now try to parse a and add a filter-match session.
   */
  if (unformat(line_input, "match %U", unformat_classify_match, cm, &match_vector, table_index) == 0)
    return 0;

  /*
   * We use hit or miss to determine whether to trace or pcap pkts
   * so the session setup is very limited
   */
  rv = vnet_classify_add_del_session(cm, table_index, match_vector, 0 /* hit_next_index */, 0 /* opaque_index */,
                                     0 /* advance */, 0 /* action */, 0 /* metadata */, 1 /* is_add */);

  vec_free(match_vector);

  return 0;
}

VLIB_CLI_COMMAND(set_vcdp_trace_filter, static) = {
  .path = "set vcdp trace filter",
  .short_help = "set vcdp trace filter",
  .function = vcdp_set_trace_filter_command_fn,
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