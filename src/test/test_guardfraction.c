/* Copyright (c) 2014-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DIRSERV_PRIVATE
#define ROUTERPARSE_PRIVATE
#define NETWORKSTATUS_PRIVATE

#include "orconfig.h"
#include "or.h"
#include "config.h"
#include "dirserv.h"
#include "container.h"
#include "entrynodes.h"
#include "util.h"
#include "routerparse.h"
#include "networkstatus.h"

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"

/** Make sure that the guardfraction bandwidths get calculated properly. */
static void
test_get_guardfraction_bandwidth(void *arg)
{
  guardfraction_bandwidth_t gf_bw;
  const int orig_bw = 1000;

  (void) arg;

  /* A guard with bandwidth 1000 and GuardFraction 0.25, should have
     bandwidth 250 as a guard and bandwidth 750 as a non-guard.  */
  guard_get_guardfraction_bandwidth(&gf_bw,
                                    orig_bw, 25);

  tt_int_op(gf_bw.guard_bw, OP_EQ, 250);
  tt_int_op(gf_bw.non_guard_bw, OP_EQ, 750);

  /* Also check the 'guard_bw + non_guard_bw == original_bw'
   * invariant. */
  tt_int_op(gf_bw.non_guard_bw + gf_bw.guard_bw, OP_EQ, orig_bw);

 done:
  ;
}

/** Parse the GuardFraction element of the consensus, and make sure it
 * gets parsed correctly. */
static void
test_parse_guardfraction_consensus(void *arg)
{
  int retval;
  or_options_t *options = get_options_mutable();

  const char *guardfraction_str_good = "GuardFraction=66";
  routerstatus_t rs_good;
  routerstatus_t rs_no_guard;

  const char *guardfraction_str_bad1 = "GuardFraction="; /* no value */
  routerstatus_t rs_bad1;

  const char *guardfraction_str_bad2 = "GuardFraction=166"; /* no percentage */
  routerstatus_t rs_bad2;

  (void) arg;

  /* GuardFraction use is currently disabled by default. So we need to
     manually enable it. */
  options->UseGuardFraction = 1;

  { /* Properly formatted GuardFraction. Check that it gets applied
       correctly. */
    memset(&rs_good, 0, sizeof(routerstatus_t));
    rs_good.is_possible_guard = 1;

    retval = routerstatus_parse_guardfraction(guardfraction_str_good,
                                              NULL, NULL,
                                              &rs_good);
    tt_int_op(retval, OP_EQ, 0);
    tt_assert(rs_good.has_guardfraction);
    tt_int_op(rs_good.guardfraction_percentage, OP_EQ, 66);
  }

  { /* Properly formatted GuardFraction but router is not a
       guard. GuardFraction should not get applied. */
    memset(&rs_no_guard, 0, sizeof(routerstatus_t));
    tt_assert(!rs_no_guard.is_possible_guard);

    setup_full_capture_of_logs(LOG_WARN);
    retval = routerstatus_parse_guardfraction(guardfraction_str_good,
                                              NULL, NULL,
                                              &rs_no_guard);
    tt_int_op(retval, OP_EQ, 0);
    tt_assert(!rs_no_guard.has_guardfraction);
    expect_single_log_msg_containing("Got GuardFraction for non-guard . "
                                     "This is not supposed to happen.");
    teardown_capture_of_logs();
  }

  { /* Bad GuardFraction. Function should fail and not apply. */
    memset(&rs_bad1, 0, sizeof(routerstatus_t));
    rs_bad1.is_possible_guard = 1;

    retval = routerstatus_parse_guardfraction(guardfraction_str_bad1,
                                              NULL, NULL,
                                              &rs_bad1);
    tt_int_op(retval, OP_EQ, -1);
    tt_assert(!rs_bad1.has_guardfraction);
  }

  { /* Bad GuardFraction. Function should fail and not apply. */
    memset(&rs_bad2, 0, sizeof(routerstatus_t));
    rs_bad2.is_possible_guard = 1;

    retval = routerstatus_parse_guardfraction(guardfraction_str_bad2,
                                              NULL, NULL,
                                              &rs_bad2);
    tt_int_op(retval, OP_EQ, -1);
    tt_assert(!rs_bad2.has_guardfraction);
  }

 done:
  teardown_capture_of_logs();
}

/** Make sure that we use GuardFraction information when we should,
 * according to the torrc option and consensus parameter. */
static void
test_should_apply_guardfraction(void *arg)
{
  networkstatus_t vote_enabled, vote_disabled, vote_missing;
  or_options_t *options = get_options_mutable();

  (void) arg;

  { /* Fill the votes for later */
    /* This one suggests enabled GuardFraction. */
    memset(&vote_enabled, 0, sizeof(vote_enabled));
    vote_enabled.net_params = smartlist_new();
    smartlist_split_string(vote_enabled.net_params,
                           "UseGuardFraction=1", NULL, 0, 0);

    /* This one suggests disabled GuardFraction. */
    memset(&vote_disabled, 0, sizeof(vote_disabled));
    vote_disabled.net_params = smartlist_new();
    smartlist_split_string(vote_disabled.net_params,
                           "UseGuardFraction=0", NULL, 0, 0);

    /* This one doesn't have GuardFraction at all. */
    memset(&vote_missing, 0, sizeof(vote_missing));
    vote_missing.net_params = smartlist_new();
    smartlist_split_string(vote_missing.net_params,
                           "leon=trout", NULL, 0, 0);
  }

  /* If torrc option is set to yes, we should always use
   * guardfraction.*/
  options->UseGuardFraction = 1;
  tt_int_op(should_apply_guardfraction(&vote_disabled), OP_EQ, 1);

  /* If torrc option is set to no, we should never use
   * guardfraction.*/
  options->UseGuardFraction = 0;
  tt_int_op(should_apply_guardfraction(&vote_enabled), OP_EQ, 0);

  /* Now let's test torrc option set to auto. */
  options->UseGuardFraction = -1;

  /* If torrc option is set to auto, and consensus parameter is set to
   * yes, we should use guardfraction. */
  tt_int_op(should_apply_guardfraction(&vote_enabled), OP_EQ, 1);

  /* If torrc option is set to auto, and consensus parameter is set to
   * no, we should use guardfraction. */
  tt_int_op(should_apply_guardfraction(&vote_disabled), OP_EQ, 0);

  /* If torrc option is set to auto, and consensus parameter is not
   * set, we should fallback to "no". */
  tt_int_op(should_apply_guardfraction(&vote_missing), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(vote_enabled.net_params, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(vote_disabled.net_params, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(vote_missing.net_params, char *, cp, tor_free(cp));
  smartlist_free(vote_enabled.net_params);
  smartlist_free(vote_disabled.net_params);
  smartlist_free(vote_missing.net_params);
}

struct testcase_t guardfraction_tests[] = {
  { "parse_guardfraction_consensus", test_parse_guardfraction_consensus,
    TT_FORK, NULL, NULL },
  { "get_guardfraction_bandwidth", test_get_guardfraction_bandwidth,
    TT_FORK, NULL, NULL },
  { "should_apply_guardfraction", test_should_apply_guardfraction,
    TT_FORK, NULL, NULL },

  END_OF_TESTCASES
};

