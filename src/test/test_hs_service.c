/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_service.c
 * \brief Test hidden service functionality.
 */

#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE

#include "test.h"
#include "crypto.h"

#include "hs/cell_establish_intro.h"
#include "hs_service.h"
#include "hs_intropoint.h"

/** We simulate the creation of an outgoing ESTABLISH_INTRO cell, and then we
 *  parse it from the receiver side. */
static void
test_establish_intro_cell(void *arg)
{
  (void) arg;
  int retval;
  char circuit_key_material[DIGEST_LEN] = {0};
  uint8_t buf[RELAY_PAYLOAD_SIZE];
  hs_cell_establish_intro_t *cell_out = NULL;
  hs_cell_establish_intro_t *cell_in = NULL;

  crypto_rand(circuit_key_material, sizeof(circuit_key_material));

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  {
    cell_out = generate_establish_intro_cell(circuit_key_material,
                                             sizeof(circuit_key_material));
    tt_assert(cell_out);

    retval = get_establish_intro_payload(buf, sizeof(buf), cell_out);
    tt_int_op(retval, >=, 0);
  }

  /* Parse it as the receiver */
  {
    ssize_t parse_result = hs_cell_establish_intro_parse(&cell_in,
                                                         buf, sizeof(buf));
    tt_int_op(parse_result, >=, 0);

    retval = verify_establish_intro_cell(cell_in,
                                         circuit_key_material,
                                         sizeof(circuit_key_material));
    tt_int_op(retval, >=, 0);
  }

 done:
  hs_cell_establish_intro_free(cell_out);
  hs_cell_establish_intro_free(cell_in);
}

struct testcase_t hs_service_tests[] = {
  { "establish_intro_cell", test_establish_intro_cell, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

