#ifndef included_vcdp_timer_lru_h
#define included_vcdp_timer_lru_h

#include <vlib/vlib.h>
#include <vppinfra/dlist.h>

#if 0
static_always_inline int
vcdp_timer_lru_free_one_with_head(vcdp_main_t *vcdp, int thread_index, f64 now, u32 head_index)
{
  vcdp_session_t *s = 0;
  dlist_elt_t *oldest_elt;
  f64 sess_timeout_time;
  u32 oldest_index;
  vcdp_per_thread_data_t *tsm = &vcdp->per_thread_data[thread_index];
  oldest_index = clib_dlist_remove_head(tsm->lru_pool, head_index);
  if (~0 != oldest_index) {
    oldest_elt = pool_elt_at_index(tsm->lru_pool, oldest_index);
    s = pool_elt_at_index(tsm->sessions, oldest_elt->value);

    sess_timeout_time = s->last_heard + (f64) vcdp_session_get_timeout(vcdp, s);
    if (now >= sess_timeout_time) {
      nat44_ed_free_session_data(vcdp, s, thread_index, 0);
      nat_ed_session_delete(vcdp, s, thread_index, 0);
      return 1;
    } else {
      clib_dlist_addhead(tsm->lru_pool, head_index, oldest_index);
    }
  }
  return 0;
}

static_always_inline int
vcdp_timer_lru_free_one(vcdp_main_t *vcdp, u32 thread_index, f64 now)
{
  vcdp_per_thread_data_t *ptd = &vcdp->per_thread_data[thread_index];
  int rc = 0;
  for (int i = 0; i < VCDP_N_TIMEOUT; i++) {
    if ((rc = vcdp_timer_lru_free_one_with_head(vcdp, thread_index, now, ptd->lru_head_index[i])) != 0) {
      return rc;
    }
  }
  return 0;
}
#endif

always_inline void
vcdp_session_timer_update(vcdp_main_t *sm, vcdp_session_t *s, u32 thread_index)
{
  /* don't update too often - timeout is in magnitude of seconds anyway */
  if (s->last_heard > s->timer.last_lru_update + 1) {
    clib_dlist_remove(sm->per_thread_data[thread_index].lru_pool, s->timer.lru_index);
    clib_dlist_addtail(sm->per_thread_data[thread_index].lru_pool, s->timer.lru_head_index, s->timer.lru_index);
    s->timer.last_lru_update = s->last_heard;
  }
}

always_inline void
vcdp_session_timer_update_timeout_type(vcdp_main_t *vcdp, vcdp_session_t *s, u32 thread_index, vcdp_timeout_type_t timeout)
{
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  s->timer.lru_head_index = ptd->lru_head_index[timeout];
  clib_dlist_remove (ptd->lru_pool, s->timer.lru_index);
  clib_dlist_addtail (ptd->lru_pool, s->timer.lru_head_index, s->timer.lru_index);
}

always_inline f64
vcdp_session_remaining_time(vcdp_session_t *s, f64 now)
{
  vcdp_main_t *vcdp = &vcdp_main;
  f64 timeout = s->last_heard + (f64) vcdp->timeouts[s->timer.type];
  f64 remaining = timeout - now;
  return remaining > 0 ? remaining : 0;
}

always_inline void
vcdp_session_timer_start(vcdp_main_t *vcdp, vcdp_session_t *s, u32 thread_index, f64 now, vcdp_timeout_type_t timeout)
{
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  dlist_elt_t *lru_list_elt;
  pool_get(ptd->lru_pool, lru_list_elt);
  s->timer.lru_index = lru_list_elt - ptd->lru_pool;
  s->timer.lru_head_index = ptd->lru_head_index[timeout];
  clib_dlist_addtail(ptd->lru_pool, s->timer.lru_head_index, s->timer.lru_index);
  lru_list_elt->value = s - ptd->sessions;
  s->timer.last_lru_update = now;
}

always_inline void
vcdp_session_timer_stop(vcdp_main_t *vcdp, vcdp_session_t *s, u32 thread_index)
{
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  clib_dlist_remove(ptd->lru_pool, s->timer.lru_index);
  pool_put_index(ptd->lru_pool, s->timer.lru_index);
}

#endif