/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_intropoint.c
 * \brief Test HS intro point functionality.
 */

#define HS_INTROPOINT_PRIVATE

#include "test.h"

#include "or.h"
#include "circuitlist.h"
#include "crypto_curve25519.h"

#include "hs_establish_intro.h"
#include "hs_circuitmap.h"
#include "hs_intropoint.h"

static void
test_circuitmap(void *arg)
{
  (void) arg;
  ed25519_public_key_t pub1;
  ed25519_secret_key_t sec1;

  or_circuit_t *circ1 = or_circuit_new(0, NULL);
  TO_CIRCUIT(circ1)->purpose = CIRCUIT_PURPOSE_OR;
  or_circuit_t *circ2 = or_circuit_new(0, NULL);
  TO_CIRCUIT(circ2)->purpose = CIRCUIT_PURPOSE_OR;

  /* Register circ1 to circuitmap */
  {
    tt_int_op(0, OP_EQ, ed25519_secret_key_generate(&sec1, 0));
    tt_int_op(0, OP_EQ, ed25519_public_key_generate(&pub1, &sec1));

    hs_circuitmap_register_intro_circ_v3(circ1, &pub1);
  }

  /* Register circ2 to circuitmap, with same index as circ1 */
  {
    hs_circuitmap_register_intro_circ_v3(circ2, &pub1);

    /* circ2 should have pushed circ1 from the circuitmap, and removed its HS
       token as well */
    tt_assert(circ1->base_.marked_for_close);
    tt_assert(!circ1->hs_token);
  }

 done:
  ;

}


struct testcase_t hs_intropoint_tests[] = {
  { "circuitmap", test_circuitmap, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};


