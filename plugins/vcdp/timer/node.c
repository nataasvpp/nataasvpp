// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp_funcs.h>

// TODO: Why is this a forwarding node?
VLIB_NODE_FN(vcdp_timer_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  u32 session_index;
  u32 count = 0;
  f64 now = vlib_time_now(vm);
  ptd->current_time = now;
  vcdp_expire_timers(&ptd->wheel, now);
  vcdp_session_index_iterate_expired(ptd, session_index)
  {
    vcdp_session_remove_or_rearm(vcdp, ptd, thread_index, session_index);
    count += 1;
  }

  /* TODO: some logic so that we are not called too often */
  return 0;
}

VLIB_REGISTER_NODE(vcdp_timer_expire_node) = {.name = "vcdp-timer-expire",
                                              .type = VLIB_NODE_TYPE_INPUT,
                                              .state = VLIB_NODE_STATE_DISABLED};