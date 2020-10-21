/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_stats.c
 * \brief Unit tests for the statistics (reputation history) module.
 **/

#include "orconfig.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "app/config/or_state_st.h"
#include "test/rng_test_helpers.h"
#include "feature/hs/hs_cache.h"
#include "test/hs_test_helpers.h"

#include <stdio.h>

#ifdef _WIN32
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif /* defined(_WIN32) */

#include <math.h>

/* These macros pull in declarations for some functions and structures that
 * are typically file-private. */
#define CIRCUITSTATS_PRIVATE
#define CIRCUITLIST_PRIVATE
#define MAINLOOP_PRIVATE
#define STATEFILE_PRIVATE
#define REPHIST_PRIVATE

#include "core/or/or.h"
#include "lib/err/backtrace.h"
#include "lib/buf/buffers.h"
#include "core/or/circuitstats.h"
#include "app/config/config.h"
#include "test/test.h"
#include "core/mainloop/mainloop.h"
#include "lib/memarea/memarea.h"
#include "feature/stats/rephist.h"
#include "app/config/statefile.h"

/** Run unit tests for some stats code. */
static void
test_stats(void *arg)
{
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  char *s = NULL;
  int i;

  /* Start with testing exit port statistics; we shouldn't collect exit
   * stats without initializing them. */
  (void)arg;
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats, note some streams and bytes, and generate history
   * string. */
  rep_hist_exit_stats_init(now);
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  rep_hist_note_exit_stream_opened(443);
  rep_hist_note_exit_bytes(443, 100, 10000);
  rep_hist_note_exit_bytes(443, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  tt_str_op("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written 80=1,443=1,other=0\n"
             "exit-kibibytes-read 80=10,443=20,other=0\n"
             "exit-streams-opened 80=4,443=4,other=0\n",OP_EQ, s);
  tor_free(s);

  /* Add a few bytes on 10 more ports and ensure that only the top 10
   * ports are contained in the history string. */
  for (i = 50; i < 60; i++) {
    rep_hist_note_exit_bytes(i, i, i);
    rep_hist_note_exit_stream_opened(i);
  }
  s = rep_hist_format_exit_stats(now + 86400);
  tt_str_op("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written 52=1,53=1,54=1,55=1,56=1,57=1,58=1,"
             "59=1,80=1,443=1,other=1\n"
             "exit-kibibytes-read 52=1,53=1,54=1,55=1,56=1,57=1,58=1,"
             "59=1,80=10,443=20,other=1\n"
             "exit-streams-opened 52=4,53=4,54=4,55=4,56=4,57=4,58=4,"
             "59=4,80=4,443=4,other=4\n",OP_EQ, s);
  tor_free(s);

  /* Stop collecting stats, add some bytes, and ensure we don't generate
   * a history string. */
  rep_hist_exit_stats_term();
  rep_hist_note_exit_bytes(80, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Re-start stats, add some bytes, reset stats, and see what history we
   * get when observing no streams or bytes at all. */
  rep_hist_exit_stats_init(now);
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  rep_hist_reset_exit_stats(now);
  s = rep_hist_format_exit_stats(now + 86400);
  tt_str_op("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written other=0\n"
             "exit-kibibytes-read other=0\n"
             "exit-streams-opened other=0\n",OP_EQ, s);
  tor_free(s);

  /* Continue with testing connection statistics; we shouldn't collect
   * conn stats without initializing them. */
  rep_hist_note_or_conn_bytes(1, 20, 400, now);
  s = rep_hist_format_conn_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats, note bytes, and generate history string. */
  rep_hist_conn_stats_init(now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now + 5);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 10);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  s = rep_hist_format_conn_stats(now + 86400);
  tt_str_op("conn-bi-direct 2010-08-12 13:27:30 (86400 s) 0,0,1,0\n",OP_EQ, s);
  tor_free(s);

  /* Stop collecting stats, add some bytes, and ensure we don't generate
   * a history string. */
  rep_hist_conn_stats_term();
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  s = rep_hist_format_conn_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Re-start stats, add some bytes, reset stats, and see what history we
   * get when observing no bytes at all. */
  rep_hist_conn_stats_init(now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now + 5);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 10);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  rep_hist_reset_conn_stats(now);
  s = rep_hist_format_conn_stats(now + 86400);
  tt_str_op("conn-bi-direct 2010-08-12 13:27:30 (86400 s) 0,0,0,0\n",OP_EQ, s);
  tor_free(s);

  /* Continue with testing buffer statistics; we shouldn't collect buffer
   * stats without initializing them. */
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Initialize stats, add statistics for a single circuit, and generate
   * the history string. */
  rep_hist_buffer_stats_init(now);
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  tt_str_op("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 20,0,0,0,0,0,0,0,0,0\n"
             "cell-queued-cells 2.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,"
                               "0.00,0.00\n"
             "cell-time-in-queue 2,0,0,0,0,0,0,0,0,0\n"
             "cell-circuits-per-decile 1\n",OP_EQ, s);
  tor_free(s);

  /* Add nineteen more circuit statistics to the one that's already in the
   * history to see that the math works correctly. */
  for (i = 21; i < 30; i++)
    rep_hist_add_buffer_stats(2.0, 2.0, i);
  for (i = 20; i < 30; i++)
    rep_hist_add_buffer_stats(3.5, 3.5, i);
  s = rep_hist_format_buffer_stats(now + 86400);
  tt_str_op("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 29,28,27,26,25,24,23,22,21,20\n"
             "cell-queued-cells 2.75,2.75,2.75,2.75,2.75,2.75,2.75,2.75,"
                               "2.75,2.75\n"
             "cell-time-in-queue 3,3,3,3,3,3,3,3,3,3\n"
             "cell-circuits-per-decile 2\n",OP_EQ, s);
  tor_free(s);

  /* Stop collecting stats, add statistics for one circuit, and ensure we
   * don't generate a history string. */
  rep_hist_buffer_stats_term();
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  tt_ptr_op(s, OP_EQ, NULL);

  /* Re-start stats, add statistics for one circuit, reset stats, and make
   * sure that the history has all zeros. */
  rep_hist_buffer_stats_init(now);
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  rep_hist_reset_buffer_stats(now);
  s = rep_hist_format_buffer_stats(now + 86400);
  tt_str_op("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 0,0,0,0,0,0,0,0,0,0\n"
             "cell-queued-cells 0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,"
                               "0.00,0.00\n"
             "cell-time-in-queue 0,0,0,0,0,0,0,0,0,0\n"
             "cell-circuits-per-decile 0\n",OP_EQ, s);

 done:
  tor_free(s);
}

/** Run unit tests the mtbf stats code. */
static void
test_rephist_mtbf(void *arg)
{
  (void)arg;

  time_t now = 1572500000; /* 2010-10-31 05:33:20 UTC */
  time_t far_future = MAX(now, time(NULL)) + 365*24*60*60;
  int r;

  /* Make a temporary datadir for these tests */
  char *ddir_fname = tor_strdup(get_fname_rnd("datadir_mtbf"));
  tor_free(get_options_mutable()->DataDirectory);
  get_options_mutable()->DataDirectory = tor_strdup(ddir_fname);
  check_private_dir(ddir_fname, CPD_CREATE, NULL);

  rep_history_clean(far_future);

  /* No data */

  r = rep_hist_load_mtbf_data(now);
  tt_int_op(r, OP_EQ, -1);
  rep_history_clean(far_future);

  /* Blank data */

  r = rep_hist_record_mtbf_data(now, 0);
  tt_int_op(r, OP_EQ, 0);
  r = rep_hist_load_mtbf_data(now);
  tt_int_op(r, OP_EQ, 0);
  rep_history_clean(far_future);

  r = rep_hist_record_mtbf_data(now, 1);
  tt_int_op(r, OP_EQ, 0);
  r = rep_hist_load_mtbf_data(now);
  tt_int_op(r, OP_EQ, 0);
  rep_history_clean(far_future);

 done:
  rep_history_clean(far_future);
  tor_free(ddir_fname);
}

/* Test v3 metrics */
static void
test_rephist_v3_onions(void *arg)
{
  int ret;

  char *stats_string = NULL;
  char *desc1_str = NULL;
  ed25519_keypair_t signing_kp1;
  hs_descriptor_t *desc1 = NULL;

  const hs_v3_stats_t *hs_v3_stats = NULL;

  (void) arg;

  /* Initialize the subsystems */
  hs_cache_init();
  rep_hist_hs_stats_init(0);
  update_approx_time(10101010101);

  /* HS stats should be zero here */
  hs_v3_stats = rep_hist_get_hs_v3_stats();
  tt_int_op(digestmap_size(hs_v3_stats->v3_onions_seen_this_period), OP_EQ, 0);

  /* Generate a valid descriptor */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, OP_EQ, 0);
  desc1 = hs_helper_build_hs_desc_with_rev_counter(&signing_kp1, 42);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Store descriptor and check that stats got updated */
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  hs_v3_stats = rep_hist_get_hs_v3_stats();
  tt_int_op(digestmap_size(hs_v3_stats->v3_onions_seen_this_period), OP_EQ, 1);

  /* cleanup */
  hs_descriptor_free(desc1);
  tor_free(desc1_str);

  /* Generate another valid descriptor */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, OP_EQ, 0);
  desc1 = hs_helper_build_hs_desc_with_rev_counter(&signing_kp1, 42);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Store descriptor and check that stats are updated */
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  hs_v3_stats = rep_hist_get_hs_v3_stats();
  tt_int_op(digestmap_size(hs_v3_stats->v3_onions_seen_this_period), OP_EQ, 2);

  /* Check that storing the same descriptor twice does not work */
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, -1);

  /* cleanup */
  hs_descriptor_free(desc1);
  tor_free(desc1_str);

  /* Create a descriptor with the same identity key but diff rev counter and
     same blinded key */
  desc1 = hs_helper_build_hs_desc_with_rev_counter(&signing_kp1, 43);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Store descriptor and check that stats are updated */
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(digestmap_size(hs_v3_stats->v3_onions_seen_this_period), OP_EQ, 2);

  /* cleanup */
  hs_descriptor_free(desc1);
  tor_free(desc1_str);

  /* Now let's skip to four days forward so that the blinded key rolls forward */
  update_approx_time(approx_time() + 345600);

  /* Now create a descriptor with the same identity key but diff rev counter and
     different blinded key */
  desc1 = hs_helper_build_hs_desc_with_rev_counter(&signing_kp1, 44);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Store descriptor and check that stats are updated */
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(digestmap_size(hs_v3_stats->v3_onions_seen_this_period), OP_EQ, 3);

  /* cleanup */
  hs_descriptor_free(desc1);
  tor_free(desc1_str);

  stats_string = rep_hist_format_hs_stats(approx_time(), true);
  tt_assert(strstr(stats_string, "hidserv-dir-v3-onions-seen-unobfuscated 3"));

 done:
  tor_free(stats_string);
}

#define ENT(name)                                                       \
  { #name, test_ ## name , 0, NULL, NULL }
#define FORK(name)                                                      \
  { #name, test_ ## name , TT_FORK, NULL, NULL }

struct testcase_t stats_tests[] = {
  FORK(stats),
  ENT(rephist_mtbf),
  FORK(rephist_v3_onions),

  END_OF_TESTCASES
};
