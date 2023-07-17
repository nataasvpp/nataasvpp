// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_timer_h
#define included_vcdp_timer_h

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/vec.h>
typedef tw_timer_wheel_1t_3w_1024sl_ov_t vcdp_tw_t;

typedef struct {
  f64 next_expiration;
  u32 handle;
} vcdp_session_timer_t;

/* Default session state protocol timeouts */
#define foreach_vcdp_timeout                                                                                           \
  _(EMBRYONIC, 5, "embryonic")                                                                                         \
  _(ESTABLISHED, 240, "established")                                                                                   \
  _(TCP_TRANSITORY, 240, "tcp-transitory")                                                                          \
  _(TCP_ESTABLISHED, 7440, "tcp-established")                                                                          \
  _(SECURITY, 30, "security") // TODO: Needed?

typedef enum {
#define _(name, val, str) VCDP_TIMEOUT_##name,
  foreach_vcdp_timeout
#undef _
    VCDP_N_TIMEOUT
} vcdp_timeout_type_t;

#define vcdp_timer_start_internal  tw_timer_start_1t_3w_1024sl_ov
#define vcdp_timer_stop_internal   tw_timer_stop_1t_3w_1024sl_ov
#define vcdp_timer_update_internal tw_timer_update_1t_3w_1024sl_ov
#define vcdp_expire_timers         tw_timer_expire_timers_1t_3w_1024sl_ov
// #define VCDP_TIMER_SI_MASK         (0x7fffffff)
#define VCDP_TIMER_INTERVAL        ((f64) 1.0) /*in seconds*/

static_always_inline void
vcdp_tw_init(vcdp_tw_t *tw, void *expired_timer_callback, f64 timer_interval, u32 max_expirations)
{
  tw_timer_wheel_init_1t_3w_1024sl_ov(tw, expired_timer_callback, timer_interval, max_expirations);
}

static_always_inline void
vcdp_session_timer_start(vcdp_tw_t *tw, vcdp_session_timer_t *timer, u32 session_index, f64 now, u32 ticks)
{
  timer->handle = vcdp_timer_start_internal(tw, session_index, 0, ticks);
  timer->next_expiration = now + ticks * VCDP_TIMER_INTERVAL;
}

static_always_inline void
vcdp_session_timer_stop(vcdp_tw_t *tw, vcdp_session_timer_t *timer)
{
  vcdp_timer_stop_internal(tw, timer->handle);
}

static_always_inline void
vcdp_session_timer_update(vcdp_tw_t *tw, vcdp_session_timer_t *timer, f64 now, u32 ticks)
{
  timer->next_expiration = now + ticks * VCDP_TIMER_INTERVAL;
}

static_always_inline void
vcdp_session_timer_update_maybe_past(vcdp_tw_t *tw, vcdp_session_timer_t *timer, u32 session_index, f64 now, u32 ticks)
{
    ASSERT(ticks>0);
    if (tw_timer_handle_is_free_1t_3w_1024sl_ov(tw, timer->handle) || timer->handle == ~0) {
      // restart timer
      vcdp_session_timer_start(tw, timer, session_index, now, ticks);
    } else {
      // update timer
      vcdp_timer_update_internal(tw, timer->handle, ticks);
    }
    timer->next_expiration = now + ticks * VCDP_TIMER_INTERVAL;
}

static_always_inline bool
vcdp_session_timer_running(vcdp_tw_t *tw, vcdp_session_timer_t *timer)
{
  if (pool_is_free_index (tw->timers, timer->handle))
    return false;
  return true;
}

#endif