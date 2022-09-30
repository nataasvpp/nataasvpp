#include <vcdp_services/tcp-check/tcp_check.h>

vcdp_tcp_check_main_t vcdp_tcp;

static clib_error_t *
vcdp_tcp_check_init(vlib_main_t *vm) {
  vlib_thread_main_t *tm = vlib_get_thread_main();
  vcdp_tcp_check_main_t *vtcm = &vcdp_tcp;
  vcdp_tcp_check_per_thread_data_t *ptd;
  vec_validate(vtcm->ptd, tm->n_vlib_mains - 1);
  vec_foreach (ptd, vtcm->ptd)
    vec_validate(ptd->state, 1ULL << VCDP_LOG2_SESSIONS_PER_THREAD);
  return 0;
};

VLIB_INIT_FUNCTION(vcdp_tcp_check_init);
