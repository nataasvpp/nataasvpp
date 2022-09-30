#include <vlib/vlib.h>
#include <vppinfra/ptclosure.h>
#include <vcdp/common.h>
#include <vcdp/service.h>

static clib_error_t *
vcdp_service_init(vlib_main_t *vm) {
  vcdp_service_main_t *sm = &vcdp_service_main;
  vcdp_service_registration_t **services = 0;
  vcdp_service_registration_t *current_reg;
  uword *index_reg_by_name = hash_create_string(0, sizeof(uword));
  uword *service_index_by_name = hash_create_string(0, sizeof(uword));
  u8 **runs_after_table = 0;
  u8 **closure = 0;
  uword *ordered_indices = 0;
  uword current_index = 0;
  current_reg = sm->next_service;

  /* Parse the registrations linked list */
  while (current_reg) {
    const char *name = current_reg->node_name;
    uword *res = hash_get_mem(index_reg_by_name, name);
    if (res)
      clib_panic("Trying to register %s twice!", name);
    vec_add1(services, current_reg);
    hash_set_mem(index_reg_by_name, name, current_index);
    current_index++;
    current_reg = current_reg->next;
  }
  /* Build the constraints matrix */
  current_reg = services[0];
  runs_after_table = clib_ptclosure_alloc(current_index);
  while (current_index > 0) {
    char **current_target;
    current_index--;
    current_reg = vec_elt_at_index(services, current_index)[0];
    /* Process runs_before and runs_after constraints */
    current_target = current_reg->runs_before;
    while (current_target[0]) {
      uword *res = hash_get_mem(index_reg_by_name, current_target[0]);
      if (res)
        runs_after_table[res[0]][current_index] = 1;
      current_target++;
    }
    current_target = current_reg->runs_after;
    while (current_target[0]) {
      uword *res = hash_get_mem(index_reg_by_name, current_target[0]);
      if (res)
        runs_after_table[current_index][res[0]] = 1;
      current_target++;
    }
  }
  hash_free(index_reg_by_name);
  closure = clib_ptclosure(runs_after_table);
again:
  for (int i = 0; i < vec_len(services); i++) {
    for (int j = 0; j < vec_len(services); j++) {
      if (closure[i][j]) {
        /* i runs after j so it can't be output */
        goto skip_i;
      }
    }
    /* i doesn't run after any pending element so it can be output */
    vec_add1(ordered_indices, i);
    for (int j = 0; j < vec_len(services); j++)
      closure[j][i] = 0;
    closure[i][i] = 1;
    goto again;
  skip_i:;
  }
  if (vec_len(services) != vec_len(ordered_indices))
    clib_panic("Failed to build total order for vcdp services");
  clib_ptclosure_free(runs_after_table);
  clib_ptclosure_free(closure);
  vec_resize(sm->services, vec_len(services));
  for (uword i = 0; i < vec_len(ordered_indices); i++) {
    current_reg = vec_elt_at_index(services, ordered_indices[i])[0];
    *current_reg->index_in_bitmap = i;
    *current_reg->service_mask = 1 << i;
    sm->services[i] = current_reg;
    hash_set_mem(service_index_by_name, current_reg->node_name, i);
  }
  sm->service_index_by_name = service_index_by_name;
  vec_free(services);
  vec_free(ordered_indices);
  /*Build the graph*/
  services = sm->services;
  for (uword i = 0; i < vec_len(services); i++) {
    vcdp_service_registration_t *reg_i = vec_elt_at_index(services, i)[0];
    vlib_node_t *node_i = vlib_get_node_by_name(vm, (u8 *) reg_i->node_name);
    if (node_i == 0)
      continue;
    if (reg_i->is_terminal)
      continue;
    vcdp_service_next_indices_init(vm, node_i->index);
  }

  return 0;
}

void
vcdp_service_next_indices_init(vlib_main_t *vm, uword node_index) {
  vcdp_service_main_t *sm = &vcdp_service_main;
  vcdp_service_registration_t **services = sm->services;
  for (uword i = 0; i < vec_len(services); i++) {
    vcdp_service_registration_t *reg = vec_elt_at_index(services, i)[0];
    vlib_node_t *node = vlib_get_node_by_name(vm, (u8 *) reg->node_name);
    if (node)
      vlib_node_add_next_with_slot(vm, node_index, node->index,
                                   *reg->index_in_bitmap);
  }
}

VLIB_INIT_FUNCTION(vcdp_service_init);
vcdp_service_main_t vcdp_service_main;