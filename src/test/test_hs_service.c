/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_descriptor.c
 * \brief Test hidden service descriptor encoding and decoding.
 */

#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE

#include "test.h"
#include "crypto.h"

#include "hs_establish_intro.h"
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
  const size_t buf_len = RELAY_PAYLOAD_SIZE;
  uint8_t buf[buf_len];

  crypto_rand(circuit_key_material, sizeof(circuit_key_material));

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  {
    hs_establish_intro_cell_t *cell_out = NULL;
    cell_out = generate_establish_intro_cell(circuit_key_material, sizeof(circuit_key_material));
    tt_assert(cell_out);

    retval = get_establish_intro_payload(buf, buf_len, cell_out);
    tt_int_op(retval, >=, 0);
  }

  /* Parse it as the receiver */
  {
    hs_establish_intro_cell_t *cell_in = NULL;
    ssize_t parse_result = hs_establish_intro_cell_parse(&cell_in,
                                                         buf, buf_len);
    tt_int_op(parse_result, >=, 0);

    retval = verify_establish_intro_cell(cell_in,
                                         circuit_key_material,
                                         sizeof(circuit_key_material));
    tt_int_op(retval, >=, 0);
  }

 done: ;
}

struct testcase_t hs_service_tests[] = {
  { "establish_intro_cell", test_establish_intro_cell, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

