/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_descriptor.c
 * \brief Test hidden service descriptor encoding and decoding.
 */

#define HS_SERVICE_PRIVATE

#include "test.h"

#include "hs_establish_intro.h"
#include "hs_service.h"
#include "crypto.h"

static void
test_establish_intro_cell(void *arg)
{
  (void) arg;
  hs_establish_intro_cell_t *cell = NULL;
  char circuit_key_material[DIGEST_LEN] = {0};

  cell = generate_establish_intro_cell(circuit_key_material, sizeof(circuit_key_material));
  tt_assert(cell);

 done: ;
}

struct testcase_t hs_service_tests[] = {
  { "establish_intro_cell", test_establish_intro_cell, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

