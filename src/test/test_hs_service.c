/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_service.c
 * \brief Test hidden service functionality.
 */

#define CONFIG_PRIVATE
#define HS_COMMON_PRIVATE
#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"

#include "config.h"
#include "crypto.h"

#include "hs/cell_establish_intro.h"
#include "hs_common.h"
#include "hs_config.h"
#include "hs_service.h"
#include "hs_intropoint.h"
#include "rendservice.h"

/* Helper: from a set of options in conf, configure a service which will add
 * it to the staging list of the HS subsytem. */
static int
helper_config_service(const char *conf)
{
  int ret = 0;
  or_options_t *options = NULL;
  tt_assert(conf);
  options = helper_parse_options(conf);
  tt_assert(options);
  ret = hs_config_service_all(options, 0);
 done:
  or_options_free(options);
  return ret;
}

static void
test_load_keys(void *arg)
{
  int ret;
  char *conf = NULL;
  char *hsdir_v2 = tor_strdup(get_fname("hs2"));
  char *hsdir_v3 = tor_strdup(get_fname("hs3"));
  char addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];

  (void) arg;

  /* We'll register two services, a v2 and a v3, then we'll load keys and
   * validate that both are in a correct state. */

  hs_init();

#define conf_fmt \
  "HiddenServiceDir %s\n" \
  "HiddenServiceVersion %d\n" \
  "HiddenServicePort 65535\n"

  /* v2 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v2, HS_VERSION_TWO);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* This one should now be registered into the v2 list. */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 0);
  tt_int_op(num_rend_services(), OP_EQ, 1);

  /* v3 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v3, HS_VERSION_THREE);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* It's in staging? */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 1);

  /* Load the keys for these. After that, the v3 service should be registered
   * in the global map. */
  hs_service_load_all_keys();
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  hs_service_t *s = get_first_service();
  tt_assert(s);

  /* Ok we have the service object. Validate few things. */
  tt_assert(!tor_mem_is_zero(s->onion_address, sizeof(s->onion_address)));
  tt_int_op(hs_address_is_valid(s->onion_address), OP_EQ, 1);
  tt_assert(!tor_mem_is_zero((char *) s->keys.identity_sk.seckey,
                             ED25519_SECKEY_LEN));
  tt_assert(!tor_mem_is_zero((char *) s->keys.identity_pk.pubkey,
                             ED25519_PUBKEY_LEN));
  /* Check onion address from identity key. */
  hs_build_address(&s->keys.identity_pk, s->version, addr);
  tt_int_op(hs_address_is_valid(addr), OP_EQ, 1);
  tt_str_op(addr, OP_EQ, s->onion_address);

 done:
  tor_free(hsdir_v2);
  tor_free(hsdir_v3);
  hs_free_all();
}

static void
test_access_service(void *arg)
{
  int ret;
  char *conf = NULL;
  char *hsdir_v3 = tor_strdup(get_fname("hs3"));
  hs_service_ht *global_map;

  (void) arg;

  /* We'll register two services, a v2 and a v3, then we'll load keys and
   * validate that both are in a correct state. */

  hs_init();

#define conf_fmt \
  "HiddenServiceDir %s\n" \
  "HiddenServiceVersion %d\n" \
  "HiddenServicePort 65535\n"

  /* v3 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v3, HS_VERSION_THREE);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* It's in staging? */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 1);

  /* Load the keys for these. After that, the v3 service should be registered
   * in the global map. */
  hs_service_load_all_keys();
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  hs_service_t *s = get_first_service();
  tt_assert(s);
  global_map = get_hs_service_map();
  tt_assert(global_map);

  /* From here, we'll try the service accessors. */
  hs_service_t *query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(query);
  tt_mem_op(query, OP_EQ, s, sizeof(hs_service_t));
  /* Remove service, check if it actually works and then put it back. */
  remove_service(global_map, s);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 0);
  query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(!query);

  /* Register back the service in the map. */
  ret = register_service(global_map, s);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  /* Twice should fail. */
  ret = register_service(global_map, s);
  tt_int_op(ret, OP_EQ, -1);
  /* Modify key of service and we should be able to put it back in. */
  s->keys.identity_pk.pubkey[1] = '\x42';
  ret = register_service(global_map, s);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 2);
  /* Remove service from map so we don't double free on cleanup. */
  remove_service(global_map, s);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(!query);
  /* Let's try to remove twice for fun. */
  setup_full_capture_of_logs(LOG_WARN);
  remove_service(global_map, s);
  expect_log_msg_containing("Could not find service in the global map");
  teardown_capture_of_logs();

 done:
  tor_free(hsdir_v3);
  hs_free_all();
}

struct testcase_t hs_service_tests[] = {
  { "load_keys", test_load_keys, TT_FORK,
    NULL, NULL },
  { "access_service", test_access_service, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

