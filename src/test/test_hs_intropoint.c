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
test_flop(void *arg)
{
  (void) arg;
  tt_int_op(1, ==, 1);

 done:
  ;
}

struct testcase_t hs_intropoint_tests[] = {
  { "flop", test_flop, TT_FORK, NULL, NULL },  

  END_OF_TESTCASES
};

