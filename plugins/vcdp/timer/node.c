/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vcdp/vcdp_funcs.h>

#define foreach_vcdp_timer_expire_error _(EXPIRED, "session expired")

typedef enum {
#define _(sym, str) VCDP_TIMER_EXPIRE_ERROR_##sym,
  foreach_vcdp_timer_expire_error
#undef _
    VCDP_TIMER_EXPIRE_N_ERROR,
} vcdp_timer_expire_error_t;

static char *vcdp_timer_expire_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_timer_expire_error
#undef _
};

VLIB_NODE_FN(vcdp_timer_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index(vcdp->per_thread_data, thread_index);
  u32 session_index;
  u32 count = 0;
  f64 now = vlib_time_now(vm);
  ptd->current_time = now;
  vcdp_expire_timers(&ptd->wheel, now);
  vcdp_session_index_iterate_expired(ptd, session_index) {
    vcdp_session_remove_or_rearm(vcdp, ptd, thread_index, session_index);
    count += 1;
  }
  if (PREDICT_FALSE(count))
    vlib_node_increment_counter(vm, node->node_index,
                                VCDP_TIMER_EXPIRE_ERROR_EXPIRED, count);

  /* TODO: some logic so that we are not called too often */
  return 0;
}

VLIB_REGISTER_NODE(vcdp_timer_expire_node) = {
  .name = "vcdp-timer-expire",
  .type = VLIB_NODE_TYPE_INPUT,
  .n_errors = VCDP_TIMER_EXPIRE_N_ERROR,
  .error_strings = vcdp_timer_expire_error_strings,
  .state = VLIB_NODE_STATE_DISABLED};