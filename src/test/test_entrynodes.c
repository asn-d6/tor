/* Copyright (c) 2014-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define STATEFILE_PRIVATE
#define ENTRYNODES_PRIVATE
#define ROUTERLIST_PRIVATE

#include "or.h"
#include "test.h"

#include "bridges.h"
#include "config.h"
#include "entrynodes.h"
#include "nodelist.h"
#include "networkstatus.h"
#include "policies.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "statefile.h"
#include "util.h"

#include "test_helpers.h"
#include "log_test_helpers.h"

/* TODO:
 * choose_random_entry() test with state set.
 *
 * parse_state() tests with more than one guards.
 *
 * More tests for set_from_config(): Multiple nodes, use fingerprints,
 *                                   use country codes.
 */

/** Dummy Tor state used in unittests. */
static or_state_t *dummy_state = NULL;
static or_state_t *
get_or_state_replacement(void)
{
  return dummy_state;
}

/* Unittest cleanup function: Cleanup the fake network. */
static int
fake_network_cleanup(const struct testcase_t *testcase, void *ptr)
{
  (void) testcase;
  (void) ptr;

  routerlist_free_all();
  nodelist_free_all();
  entry_guards_free_all();
  or_state_free(dummy_state);

  return 1; /* NOP */
}

/* Unittest setup function: Setup a fake network. */
static void *
fake_network_setup(const struct testcase_t *testcase)
{
  (void) testcase;

  /* Setup fake state */
  dummy_state = tor_malloc_zero(sizeof(or_state_t));
  MOCK(get_or_state,
       get_or_state_replacement);

  /* Setup fake routerlist. */
  helper_setup_fake_routerlist();

  /* Return anything but NULL (it's interpreted as test fail) */
  return dummy_state;
}

static networkstatus_t *dummy_consensus = NULL;

static smartlist_t *big_fake_net_nodes = NULL;

static smartlist_t *
bfn_mock_nodelist_get_list(void)
{
  return big_fake_net_nodes;
}

static networkstatus_t *
bfn_mock_networkstatus_get_live_consensus(time_t now)
{
  (void)now;
  return dummy_consensus;
}

static const node_t *
bfn_mock_node_get_by_id(const char *id)
{
  SMARTLIST_FOREACH(big_fake_net_nodes, node_t *, n,
                    if (fast_memeq(n->identity, id, 20))
                      return n);

  return NULL;
}

/* Unittest cleanup function: Cleanup the fake network. */
static int
big_fake_network_cleanup(const struct testcase_t *testcase, void *ptr)
{
  (void) testcase;
  (void) ptr;

  if (big_fake_net_nodes) {
    SMARTLIST_FOREACH(big_fake_net_nodes, node_t *, n, {
      tor_free(n->rs);
      tor_free(n->md);
      tor_free(n);
    });
    smartlist_free(big_fake_net_nodes);
  }

  UNMOCK(nodelist_get_list);
  UNMOCK(node_get_by_id);
  UNMOCK(get_or_state);
  UNMOCK(networkstatus_get_live_consensus);
  or_state_free(dummy_state);
  dummy_state = NULL;
  tor_free(dummy_consensus);

  return 1; /* NOP */
}

/* Unittest setup function: Setup a fake network. */
static void *
big_fake_network_setup(const struct testcase_t *testcase)
{
  int i;

  /* These are minimal node_t objects that only contain the aspects of node_t
   * that we need for entrynodes.c. */
  const int N_NODES = 271;

  big_fake_net_nodes = smartlist_new();
  for (i = 0; i < N_NODES; ++i) {
    node_t *n = tor_malloc_zero(sizeof(node_t));
    n->md = tor_malloc_zero(sizeof(microdesc_t));

    crypto_rand(n->identity, sizeof(n->identity));
    n->rs = tor_malloc_zero(sizeof(routerstatus_t));

    memcpy(n->rs->identity_digest, n->identity, DIGEST_LEN);

    n->is_running = n->is_valid = n->is_fast = n->is_stable = 1;

    n->rs->addr = 0x04020202;
    n->rs->or_port = 1234;
    n->rs->is_v2_dir = 1;
    n->rs->has_bandwidth = 1;
    n->rs->bandwidth_kb = 30;

    /* Call half of the nodes a possible guard. */
    if (i % 2 == 0) {
      n->is_possible_guard = 1;
      n->rs->guardfraction_percentage = 100;
      n->rs->has_guardfraction = 1;
    }

    smartlist_add(big_fake_net_nodes, n);
  }

  dummy_state = tor_malloc_zero(sizeof(or_state_t));
  dummy_consensus = tor_malloc_zero(sizeof(networkstatus_t));
  dummy_consensus->valid_after = approx_time() - 3600;
  dummy_consensus->valid_until = approx_time() + 3600;

  MOCK(nodelist_get_list, bfn_mock_nodelist_get_list);
  MOCK(node_get_by_id, bfn_mock_node_get_by_id);
  MOCK(get_or_state,
       get_or_state_replacement);
  MOCK(networkstatus_get_live_consensus,
       bfn_mock_networkstatus_get_live_consensus);
  /* Return anything but NULL (it's interpreted as test fail) */
  return (void*)testcase;
}

static time_t
mock_randomize_time_no_randomization(time_t a, time_t b)
{
  (void) b;
  return a;
}

static or_options_t mocked_options;

static const or_options_t *
mock_get_options(void)
{
  return &mocked_options;
}

/** Test choose_random_entry() with none of our routers being guard nodes. */
static void
test_choose_random_entry_no_guards(void *arg)
{
  const node_t *chosen_entry = NULL;

  (void) arg;

  MOCK(get_options, mock_get_options);

  /* Check that we get a guard if it passes preferred
   * address settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientPreferIPv6ORPort = 0;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  /* Try to pick an entry even though none of our routers are guards. */
  chosen_entry = choose_random_entry(NULL);

  /* Unintuitively, we actually pick a random node as our entry,
     because router_choose_random_node() relaxes its constraints if it
     can't find a proper entry guard. */
  tt_assert(chosen_entry);

  /* And with the other IP version active */
  mocked_options.ClientUseIPv6 = 1;
  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

  /* And with the preference on auto */
  mocked_options.ClientPreferIPv6ORPort = -1;
  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

  /* Check that we don't get a guard if it doesn't pass mandatory address
   * settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 0;
  mocked_options.ClientPreferIPv6ORPort = 0;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);

  /* If we don't allow IPv4 at all, we don't get a guard*/
  tt_assert(!chosen_entry);

  /* Check that we get a guard if it passes allowed but not preferred address
   * settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientUseIPv6 = 1;
  mocked_options.ClientPreferIPv6ORPort = 1;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

  /* Check that we get a guard if it passes preferred address settings when
   * they're auto */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientPreferIPv6ORPort = -1;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

  /* And with IPv6 active */
  mocked_options.ClientUseIPv6 = 1;

  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

 done:
  memset(&mocked_options, 0, sizeof(mocked_options));
  UNMOCK(get_options);
}

/** Test choose_random_entry() with only one of our routers being a
    guard node. */
static void
test_choose_random_entry_one_possible_guard(void *arg)
{
  const node_t *chosen_entry = NULL;
  node_t *the_guard = NULL;
  smartlist_t *our_nodelist = NULL;

  (void) arg;

  MOCK(get_options, mock_get_options);

  /* Set one of the nodes to be a guard. */
  our_nodelist = nodelist_get_list();
  the_guard = smartlist_get(our_nodelist, 4); /* chosen by fair dice roll */
  the_guard->is_possible_guard = 1;

  /* Check that we get the guard if it passes preferred
   * address settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientPreferIPv6ORPort = 0;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  /* Pick an entry. Make sure we pick the node we marked as guard. */
  chosen_entry = choose_random_entry(NULL);
  tt_ptr_op(chosen_entry, OP_EQ, the_guard);

  /* And with the other IP version active */
  mocked_options.ClientUseIPv6 = 1;
  chosen_entry = choose_random_entry(NULL);
  tt_ptr_op(chosen_entry, OP_EQ, the_guard);

  /* And with the preference on auto */
  mocked_options.ClientPreferIPv6ORPort = -1;
  chosen_entry = choose_random_entry(NULL);
  tt_ptr_op(chosen_entry, OP_EQ, the_guard);

  /* Check that we don't get a guard if it doesn't pass mandatory address
   * settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 0;
  mocked_options.ClientPreferIPv6ORPort = 0;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);

  /* If we don't allow IPv4 at all, we don't get a guard*/
  tt_assert(!chosen_entry);

  /* Check that we get a node if it passes allowed but not preferred
   * address settings */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientUseIPv6 = 1;
  mocked_options.ClientPreferIPv6ORPort = 1;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);

  /* We disable the guard check and the preferred address check at the same
   * time, so we can't be sure we get the guard */
  tt_assert(chosen_entry);

  /* Check that we get a node if it is allowed but not preferred when settings
   * are auto */
  memset(&mocked_options, 0, sizeof(mocked_options));
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientPreferIPv6ORPort = -1;
  mocked_options.UseDeprecatedGuardAlgorithm = 1;

  chosen_entry = choose_random_entry(NULL);

  /* We disable the guard check and the preferred address check at the same
   * time, so we can't be sure we get the guard */
  tt_assert(chosen_entry);

  /* and with IPv6 active */
  mocked_options.ClientUseIPv6 = 1;

  chosen_entry = choose_random_entry(NULL);
  tt_assert(chosen_entry);

 done:
  memset(&mocked_options, 0, sizeof(mocked_options));
  UNMOCK(get_options);
}

/** Helper to conduct tests for populate_live_entry_guards().

   This test adds some entry guards to our list, and then tests
   populate_live_entry_guards() to mke sure it filters them correctly.

   <b>num_needed</b> is the number of guard nodes we support. It's
   configurable to make sure we function properly with 1 or 3 guard
   nodes configured.
*/
static void
populate_live_entry_guards_test_helper(int num_needed)
{
  smartlist_t *our_nodelist = NULL;
  smartlist_t *live_entry_guards = smartlist_new();
  guard_selection_t *gs = get_guard_selection_info();
  const smartlist_t *all_entry_guards =
    get_entry_guards_for_guard_selection(gs);
  or_options_t *options = get_options_mutable();
  int retval;

  /* Set NumEntryGuards to the provided number. */
  options->NumEntryGuards = num_needed;
  tt_int_op(num_needed, OP_EQ, decide_num_guards(options, 0));

  /* The global entry guards smartlist should be empty now. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 0);

  /* Walk the nodelist and add all nodes as entry guards. */
  our_nodelist = nodelist_get_list();
  tt_int_op(smartlist_len(our_nodelist), OP_EQ, HELPER_NUMBER_OF_DESCRIPTORS);

  SMARTLIST_FOREACH_BEGIN(our_nodelist, const node_t *, node) {
    const node_t *node_tmp;
    node_tmp = add_an_entry_guard(gs, node, 0, 1, 0, 0);
    tt_assert(node_tmp);
  } SMARTLIST_FOREACH_END(node);

  /* Make sure the nodes were added as entry guards. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ,
            HELPER_NUMBER_OF_DESCRIPTORS);

  /* Ensure that all the possible entry guards are enough to satisfy us. */
  tt_int_op(smartlist_len(all_entry_guards), OP_GE, num_needed);

  /* Walk the entry guard list for some sanity checking */
  SMARTLIST_FOREACH_BEGIN(all_entry_guards, const entry_guard_t *, entry) {
    /* Since we called add_an_entry_guard() with 'for_discovery' being
       False, all guards should have made_contact enabled. */
    tt_int_op(entry->made_contact, OP_EQ, 1);

  } SMARTLIST_FOREACH_END(entry);

  /* First, try to get some fast guards. This should fail. */
  retval = populate_live_entry_guards(live_entry_guards,
                                      all_entry_guards,
                                      NULL,
                                      NO_DIRINFO, /* Don't care about DIRINFO*/
                                      0, 0,
                                      1); /* We want fast guard! */
  tt_int_op(retval, OP_EQ, 0);
  tt_int_op(smartlist_len(live_entry_guards), OP_EQ, 0);

  /* Now try to get some stable guards. This should fail too. */
  retval = populate_live_entry_guards(live_entry_guards,
                                      all_entry_guards,
                                      NULL,
                                      NO_DIRINFO,
                                      0,
                                      1, /* We want stable guard! */
                                      0);
  tt_int_op(retval, OP_EQ, 0);
  tt_int_op(smartlist_len(live_entry_guards), OP_EQ, 0);

  /* Now try to get any guard we can find. This should succeed. */
  retval = populate_live_entry_guards(live_entry_guards,
                                      all_entry_guards,
                                      NULL,
                                      NO_DIRINFO,
                                      0, 0, 0); /* No restrictions! */

  /* Since we had more than enough guards in 'all_entry_guards', we
     should have added 'num_needed' of them to live_entry_guards.
     'retval' should be 1 since we now have enough live entry guards
     to pick one.  */
  tt_int_op(retval, OP_EQ, 1);
  tt_int_op(smartlist_len(live_entry_guards), OP_EQ, num_needed);

 done:
  smartlist_free(live_entry_guards);
}

/* Test populate_live_entry_guards() for 1 guard node. */
static void
test_populate_live_entry_guards_1guard(void *arg)
{
  (void) arg;

  populate_live_entry_guards_test_helper(1);
}

/* Test populate_live_entry_guards() for 3 guard nodes. */
static void
test_populate_live_entry_guards_3guards(void *arg)
{
  (void) arg;

  populate_live_entry_guards_test_helper(3);
}

/** Append some EntryGuard lines to the Tor state at <b>state</b>.

   <b>entry_guard_lines</b> is a smartlist containing 2-tuple
   smartlists that carry the key and values of the statefile.
   As an example:
   entry_guard_lines =
     (("EntryGuard", "name 67E72FF33D7D41BF11C569646A0A7B4B188340DF DirCache"),
      ("EntryGuardDownSince", "2014-06-07 16:02:46 2014-06-07 16:02:46"))
*/
static void
state_insert_entry_guard_helper(or_state_t *state,
                                smartlist_t *entry_guard_lines)
{
  config_line_t **next, *line;

  next = &state->EntryGuards;
  *next = NULL;

  /* Loop over all the state lines in the smartlist */
  SMARTLIST_FOREACH_BEGIN(entry_guard_lines, const smartlist_t *,state_lines) {
    /* Get key and value for each line */
    const char *state_key = smartlist_get(state_lines, 0);
    const char *state_value = smartlist_get(state_lines, 1);

    *next = line = tor_malloc_zero(sizeof(config_line_t));
    line->key = tor_strdup(state_key);
    tor_asprintf(&line->value, "%s", state_value);
    next = &(line->next);
  } SMARTLIST_FOREACH_END(state_lines);
}

/** Free memory occupied by <b>entry_guard_lines</b>. */
static void
state_lines_free(smartlist_t *entry_guard_lines)
{
  SMARTLIST_FOREACH_BEGIN(entry_guard_lines, smartlist_t *, state_lines) {
    char *state_key = smartlist_get(state_lines, 0);
    char *state_value = smartlist_get(state_lines, 1);

    tor_free(state_key);
    tor_free(state_value);
    smartlist_free(state_lines);
  } SMARTLIST_FOREACH_END(state_lines);

  smartlist_free(entry_guard_lines);
}

/* Tests entry_guards_parse_state(). It creates a fake Tor state with
   a saved entry guard and makes sure that Tor can parse it and
   creates the right entry node out of it.
*/
static void
test_entry_guards_parse_state_simple(void *arg)
{
  or_options_t *options = get_options_mutable();
  options->UseDeprecatedGuardAlgorithm = 1;
  or_state_t *state = or_state_new();
  const smartlist_t *all_entry_guards = get_entry_guards();
  smartlist_t *entry_state_lines = smartlist_new();
  char *msg = NULL;
  int retval;

  /* Details of our fake guard node */
  const char *nickname = "hagbard";
  const char *fpr = "B29D536DD1752D542E1FBB3C9CE4449D51298212";
  const char *tor_version = "0.2.5.3-alpha-dev";
  const char *added_at = get_yesterday_date_str();
  const char *unlisted_since = "2014-06-08 16:16:50";

  (void) arg;

  /* The global entry guards smartlist should be empty now. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 0);

  { /* Prepare the state entry */

    /* Prepare the smartlist to hold the key/value of each line */
    smartlist_t *state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuard");
    smartlist_add_asprintf(state_line, "%s %s %s", nickname, fpr, "DirCache");
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardAddedBy");
    smartlist_add_asprintf(state_line, "%s %s %s", fpr, tor_version, added_at);
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardUnlistedSince");
    smartlist_add_asprintf(state_line, "%s", unlisted_since);
    smartlist_add(entry_state_lines, state_line);
  }

  /* Inject our lines in the state */
  state_insert_entry_guard_helper(state, entry_state_lines);

  /* Parse state */
  retval = entry_guards_parse_state(state, 1, &msg);
  tt_int_op(retval, OP_GE, 0);

  /* Test that the guard was registered.
     We need to re-get the entry guard list since its pointer was
     overwritten in entry_guards_parse_state(). */
  all_entry_guards = get_entry_guards();
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 1);

  { /* Test the entry guard structure */
    char hex_digest[1024];
    char str_time[1024];

    const entry_guard_t *e = smartlist_get(all_entry_guards, 0);
    tt_str_op(e->nickname, OP_EQ, nickname); /* Verify nickname */

    base16_encode(hex_digest, sizeof(hex_digest),
                  e->identity, DIGEST_LEN);
    tt_str_op(hex_digest, OP_EQ, fpr); /* Verify fingerprint */

    tt_assert(e->is_dir_cache); /* Verify dirness */

    tt_str_op(e->chosen_by_version, OP_EQ, tor_version); /* Verify version */

    tt_assert(e->made_contact); /* All saved guards have been contacted */

    tt_assert(e->bad_since); /* Verify bad_since timestamp */
    format_iso_time(str_time, e->bad_since);
    tt_str_op(str_time, OP_EQ, unlisted_since);

    /* The rest should be unset */
    tt_assert(!e->unreachable_since);
    tt_assert(!e->can_retry);
    tt_assert(!e->pb.path_bias_noticed);
    tt_assert(!e->pb.path_bias_warned);
    tt_assert(!e->pb.path_bias_extreme);
    tt_assert(!e->pb.path_bias_disabled);
    tt_assert(!e->pb.path_bias_use_noticed);
    tt_assert(!e->pb.path_bias_use_extreme);
    tt_assert(!e->last_attempted);
  }

 done:
  state_lines_free(entry_state_lines);
  or_state_free(state);
  tor_free(msg);
}

/** Similar to test_entry_guards_parse_state_simple() but aims to test
    the PathBias-related details of the entry guard. */
static void
test_entry_guards_parse_state_pathbias(void *arg)
{
  or_options_t *options = get_options_mutable();
  options->UseDeprecatedGuardAlgorithm = 1;
  or_state_t *state = or_state_new();
  const smartlist_t *all_entry_guards = get_entry_guards();
  char *msg = NULL;
  int retval;
  smartlist_t *entry_state_lines = smartlist_new();

  /* Path bias details of the fake guard */
  const double circ_attempts = 9;
  const double circ_successes = 8;
  const double successful_closed = 4;
  const double collapsed = 2;
  const double unusable = 0;
  const double timeouts = 1;

  (void) arg;

  /* The global entry guards smartlist should be empty now. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 0);

  { /* Prepare the state entry */

    /* Prepare the smartlist to hold the key/value of each line */
    smartlist_t *state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuard");
    smartlist_add_asprintf(state_line,
             "givethanks B29D536DD1752D542E1FBB3C9CE4449D51298212 NoDirCache");
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardAddedBy");
    smartlist_add_asprintf(state_line,
      "B29D536DD1752D542E1FBB3C9CE4449D51298212 0.2.5.3-alpha-dev "
                           "%s", get_yesterday_date_str());
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardUnlistedSince");
    smartlist_add_asprintf(state_line, "2014-06-08 16:16:50");
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardPathBias");
    smartlist_add_asprintf(state_line, "%f %f %f %f %f %f",
                           circ_attempts, circ_successes, successful_closed,
                           collapsed, unusable, timeouts);
    smartlist_add(entry_state_lines, state_line);
  }

  /* Inject our lines in the state */
  state_insert_entry_guard_helper(state, entry_state_lines);

  /* Parse state */
  retval = entry_guards_parse_state(state, 1, &msg);
  tt_int_op(retval, OP_GE, 0);

  /* Test that the guard was registered */
  all_entry_guards = get_entry_guards();
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 1);

  { /* Test the path bias of this guard */
    const entry_guard_t *e = smartlist_get(all_entry_guards, 0);

    tt_assert(!e->is_dir_cache);
    tt_assert(!e->can_retry);

    /* XXX tt_double_op doesn't support equality. Cast to int for now. */
    tt_int_op((int)e->pb.circ_attempts, OP_EQ, (int)circ_attempts);
    tt_int_op((int)e->pb.circ_successes, OP_EQ, (int)circ_successes);
    tt_int_op((int)e->pb.successful_circuits_closed, OP_EQ,
              (int)successful_closed);
    tt_int_op((int)e->pb.timeouts, OP_EQ, (int)timeouts);
    tt_int_op((int)e->pb.collapsed_circuits, OP_EQ, (int)collapsed);
    tt_int_op((int)e->pb.unusable_circuits, OP_EQ, (int)unusable);
  }

 done:
  or_state_free(state);
  state_lines_free(entry_state_lines);
  tor_free(msg);
}

/* Simple test of entry_guards_set_from_config() by specifying a
   particular EntryNode and making sure it gets picked. */
static void
test_entry_guards_set_from_config(void *arg)
{
  or_options_t *options = get_options_mutable();
  options->UseDeprecatedGuardAlgorithm = 1;
  guard_selection_t *gs = get_guard_selection_info();
  const smartlist_t *all_entry_guards =
    get_entry_guards_for_guard_selection(gs);
  const char *entrynodes_str = "test003r";
  const node_t *chosen_entry = NULL;
  int retval;

  (void) arg;

  /* Prase EntryNodes as a routerset. */
  options->EntryNodes = routerset_new();
  retval = routerset_parse(options->EntryNodes,
                           entrynodes_str,
                           "test_entrynodes");
  tt_int_op(retval, OP_GE, 0);

  /* Read nodes from EntryNodes */
  entry_guards_set_from_config(gs, options);

  /* Test that only one guard was added. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 1);

  /* Make sure it was the guard we specified. */
  chosen_entry = choose_random_entry(NULL);
  tt_str_op(chosen_entry->ri->nickname, OP_EQ, entrynodes_str);

 done:
  routerset_free(options->EntryNodes);
}

static void
test_entry_is_time_to_retry(void *arg)
{
  entry_guard_t *test_guard;
  time_t now;
  int retval;
  (void)arg;

  now = time(NULL);

  test_guard = tor_malloc_zero(sizeof(entry_guard_t));

  test_guard->last_attempted = now - 10;
  test_guard->unreachable_since = now - 1;

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->unreachable_since = now - (6*60*60 - 1);
  test_guard->last_attempted = now - (60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->last_attempted = now - (60*60 - 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,0);

  test_guard->unreachable_since = now - (6*60*60 + 1);
  test_guard->last_attempted = now - (4*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->unreachable_since = now - (3*24*60*60 - 1);
  test_guard->last_attempted = now - (4*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->unreachable_since = now - (3*24*60*60 + 1);
  test_guard->last_attempted = now - (18*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->unreachable_since = now - (7*24*60*60 - 1);
  test_guard->last_attempted = now - (18*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->last_attempted = now - (18*60*60 - 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,0);

  test_guard->unreachable_since = now - (7*24*60*60 + 1);
  test_guard->last_attempted = now - (36*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

  test_guard->unreachable_since = now - (7*24*60*60 + 1);
  test_guard->last_attempted = now - (36*60*60 + 1);

  retval = entry_is_time_to_retry(test_guard,now);
  tt_int_op(retval,OP_EQ,1);

 done:
  tor_free(test_guard);
}

/** XXX Do some tests that entry_is_live() */
static void
test_entry_is_live(void *arg)
{
  smartlist_t *our_nodelist = NULL;
  guard_selection_t *gs = get_guard_selection_info();
  const smartlist_t *all_entry_guards =
    get_entry_guards_for_guard_selection(gs);
  const node_t *test_node = NULL;
  const entry_guard_t *test_entry = NULL;
  const char *msg;
  int which_node;

  (void) arg;

  /* The global entry guards smartlist should be empty now. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ, 0);

  /* Walk the nodelist and add all nodes as entry guards. */
  our_nodelist = nodelist_get_list();
  tt_int_op(smartlist_len(our_nodelist), OP_EQ, HELPER_NUMBER_OF_DESCRIPTORS);

  SMARTLIST_FOREACH_BEGIN(our_nodelist, const node_t *, node) {
    const node_t *node_tmp;
    node_tmp = add_an_entry_guard(gs, node, 0, 1, 0, 0);
    tt_assert(node_tmp);

    tt_int_op(node->is_stable, OP_EQ, 0);
    tt_int_op(node->is_fast, OP_EQ, 0);
  } SMARTLIST_FOREACH_END(node);

  /* Make sure the nodes were added as entry guards. */
  tt_int_op(smartlist_len(all_entry_guards), OP_EQ,
            HELPER_NUMBER_OF_DESCRIPTORS);

  /* Now get a random test entry that we will use for this unit test. */
  which_node = 3;  /* (chosen by fair dice roll) */
  test_entry = smartlist_get(all_entry_guards, which_node);

  /* Let's do some entry_is_live() tests! */

  /* Require the node to be stable, but it's not. Should fail.
     Also enable 'assume_reachable' because why not. */
  test_node = entry_is_live(test_entry,
                            ENTRY_NEED_UPTIME | ENTRY_ASSUME_REACHABLE,
                            &msg);
  tt_assert(!test_node);

  /* Require the node to be fast, but it's not. Should fail. */
  test_node = entry_is_live(test_entry,
                            ENTRY_NEED_CAPACITY | ENTRY_ASSUME_REACHABLE,
                            &msg);
  tt_assert(!test_node);

  /* Don't impose any restrictions on the node. Should succeed. */
  test_node = entry_is_live(test_entry, 0, &msg);
  tt_assert(test_node);
  tt_ptr_op(test_node, OP_EQ, node_get_by_id(test_entry->identity));

  /* Require descriptor for this node. It has one so it should succeed. */
  test_node = entry_is_live(test_entry, ENTRY_NEED_DESCRIPTOR, &msg);
  tt_assert(test_node);
  tt_ptr_op(test_node, OP_EQ, node_get_by_id(test_entry->identity));

 done:
  ; /* XXX */
}

#define TEST_IPV4_ADDR "123.45.67.89"
#define TEST_IPV6_ADDR "[1234:5678:90ab:cdef::]"

static void
test_node_preferred_orport(void *arg)
{
  (void)arg;
  tor_addr_t ipv4_addr;
  const uint16_t ipv4_port = 4444;
  tor_addr_t ipv6_addr;
  const uint16_t ipv6_port = 6666;
  routerinfo_t node_ri;
  node_t node;
  tor_addr_port_t ap;

  /* Setup options */
  memset(&mocked_options, 0, sizeof(mocked_options));
  /* We don't test ClientPreferIPv6ORPort here, because it's used in
   * nodelist_set_consensus to setup node.ipv6_preferred, which we set
   * directly. */
  MOCK(get_options, mock_get_options);

  /* Setup IP addresses */
  tor_addr_parse(&ipv4_addr, TEST_IPV4_ADDR);
  tor_addr_parse(&ipv6_addr, TEST_IPV6_ADDR);

  /* Setup node_ri */
  memset(&node_ri, 0, sizeof(node_ri));
  node_ri.addr = tor_addr_to_ipv4h(&ipv4_addr);
  node_ri.or_port = ipv4_port;
  tor_addr_copy(&node_ri.ipv6_addr, &ipv6_addr);
  node_ri.ipv6_orport = ipv6_port;

  /* Setup node */
  memset(&node, 0, sizeof(node));
  node.ri = &node_ri;

  /* Check the preferred address is IPv4 if we're only using IPv4, regardless
   * of whether we prefer it or not */
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientUseIPv6 = 0;
  node.ipv6_preferred = 0;
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv4_addr));
  tt_assert(ap.port == ipv4_port);

  node.ipv6_preferred = 1;
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv4_addr));
  tt_assert(ap.port == ipv4_port);

  /* Check the preferred address is IPv4 if we're using IPv4 and IPv6, but
   * don't prefer the IPv6 address */
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientUseIPv6 = 1;
  node.ipv6_preferred = 0;
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv4_addr));
  tt_assert(ap.port == ipv4_port);

  /* Check the preferred address is IPv6 if we prefer it and
   * ClientUseIPv6 is 1, regardless of ClientUseIPv4 */
  mocked_options.ClientUseIPv4 = 1;
  mocked_options.ClientUseIPv6 = 1;
  node.ipv6_preferred = 1;
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv6_addr));
  tt_assert(ap.port == ipv6_port);

  mocked_options.ClientUseIPv4 = 0;
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv6_addr));
  tt_assert(ap.port == ipv6_port);

  /* Check the preferred address is IPv6 if we don't prefer it, but
   * ClientUseIPv4 is 0 */
  mocked_options.ClientUseIPv4 = 0;
  mocked_options.ClientUseIPv6 = 1;
  node.ipv6_preferred = fascist_firewall_prefer_ipv6_orport(&mocked_options);
  node_get_pref_orport(&node, &ap);
  tt_assert(tor_addr_eq(&ap.addr, &ipv6_addr));
  tt_assert(ap.port == ipv6_port);

 done:
  UNMOCK(get_options);
}

static void
test_entry_guard_describe(void *arg)
{
  (void)arg;
  entry_guard_t g;
  memset(&g, 0, sizeof(g));
  strlcpy(g.nickname, "okefenokee", sizeof(g.nickname));
  memcpy(g.identity, "theforestprimeval---", DIGEST_LEN);

  tt_str_op(entry_guard_describe(&g), OP_EQ,
            "okefenokee ($746865666F726573747072696D6576616C2D2D2D)");

 done:
  ;
}

static void
test_entry_guard_randomize_time(void *arg)
{
  const time_t now = 1479153573;
  const int delay = 86400;
  const int N = 1000;
  (void)arg;

  time_t t;
  int i;
  for (i = 0; i < N; ++i) {
    t = randomize_time(now, delay);
    tt_int_op(t, OP_LE, now);
    tt_int_op(t, OP_GE, now-delay);
  }

  /* now try the corner cases */
  for (i = 0; i < N; ++i) {
    t = randomize_time(100, delay);
    tt_int_op(t, OP_GE, 1);
    tt_int_op(t, OP_LE, 100);

    t = randomize_time(0, delay);
    tt_int_op(t, OP_EQ, 1);
  }

 done:
  ;
}

static void
test_entry_guard_encode_for_state_minimal(void *arg)
{
  (void) arg;
  entry_guard_t *eg = tor_malloc_zero(sizeof(entry_guard_t));

  eg->selection_name = tor_strdup("wubwub");
  memcpy(eg->identity, "plurpyflurpyslurpydo", DIGEST_LEN);
  eg->sampled_on_date = 1479081600;
  eg->confirmed_idx = -1;

  char *s = NULL;
  s = entry_guard_encode_for_state(eg);

  tt_str_op(s, OP_EQ,
            "in=wubwub "
            "rsa_id=706C75727079666C75727079736C75727079646F "
            "sampled_on=2016-11-14T00:00:00 "
            "listed=0");

 done:
  entry_guard_free(eg);
  tor_free(s);
}

static void
test_entry_guard_encode_for_state_maximal(void *arg)
{
  (void) arg;
  entry_guard_t *eg = tor_malloc_zero(sizeof(entry_guard_t));

  strlcpy(eg->nickname, "Fred", sizeof(eg->nickname));
  eg->selection_name = tor_strdup("default");
  memcpy(eg->identity, "plurpyflurpyslurpydo", DIGEST_LEN);
  eg->sampled_on_date = 1479081600;
  eg->sampled_by_version = tor_strdup("1.2.3");
  eg->unlisted_since_date = 1479081645;
  eg->currently_listed = 1;
  eg->confirmed_on_date = 1479081690;
  eg->confirmed_idx = 333;
  eg->extra_state_fields = tor_strdup("and the green grass grew all around");

  char *s = NULL;
  s = entry_guard_encode_for_state(eg);

  tt_str_op(s, OP_EQ,
            "in=default "
            "rsa_id=706C75727079666C75727079736C75727079646F "
            "nickname=Fred "
            "sampled_on=2016-11-14T00:00:00 "
            "sampled_by=1.2.3 "
            "unlisted_since=2016-11-14T00:00:45 "
            "listed=1 "
            "confirmed_on=2016-11-14T00:01:30 "
            "confirmed_idx=333 "
            "and the green grass grew all around");

 done:
  entry_guard_free(eg);
  tor_free(s);
}

static void
test_entry_guard_parse_from_state_minimal(void *arg)
{
  (void)arg;
  char *mem_op_hex_tmp = NULL;
  entry_guard_t *eg = NULL;
  time_t t = approx_time();

  eg = entry_guard_parse_from_state(
                 "in=default_plus "
                 "rsa_id=596f75206d6179206e656564206120686f626279");
  tt_assert(eg);

  tt_str_op(eg->selection_name, OP_EQ, "default_plus");
  test_mem_op_hex(eg->identity, OP_EQ,
                  "596f75206d6179206e656564206120686f626279");
  tt_str_op(eg->nickname, OP_EQ, "$596F75206D6179206E656564206120686F626279");
  tt_i64_op(eg->sampled_on_date, OP_GE, t);
  tt_i64_op(eg->sampled_on_date, OP_LE, t+86400);
  tt_i64_op(eg->unlisted_since_date, OP_EQ, 0);
  tt_ptr_op(eg->sampled_by_version, OP_EQ, NULL);
  tt_int_op(eg->currently_listed, OP_EQ, 0);
  tt_i64_op(eg->confirmed_on_date, OP_EQ, 0);
  tt_int_op(eg->confirmed_idx, OP_EQ, -1);

  tt_int_op(eg->last_tried_to_connect, OP_EQ, 0);
  tt_int_op(eg->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

 done:
  entry_guard_free(eg);
  tor_free(mem_op_hex_tmp);
}

static void
test_entry_guard_parse_from_state_maximal(void *arg)
{
  (void)arg;
  char *mem_op_hex_tmp = NULL;
  entry_guard_t *eg = NULL;

  eg = entry_guard_parse_from_state(
            "in=fred "
            "rsa_id=706C75727079666C75727079736C75727079646F "
            "nickname=Fred "
            "sampled_on=2016-11-14T00:00:00 "
            "sampled_by=1.2.3 "
            "unlisted_since=2016-11-14T00:00:45 "
            "listed=1 "
            "confirmed_on=2016-11-14T00:01:30 "
            "confirmed_idx=333 "
            "and the green grass grew all around "
            "rsa_id=all,around");
  tt_assert(eg);

  test_mem_op_hex(eg->identity, OP_EQ,
                  "706C75727079666C75727079736C75727079646F");
  tt_str_op(eg->nickname, OP_EQ, "Fred");
  tt_i64_op(eg->sampled_on_date, OP_EQ, 1479081600);
  tt_i64_op(eg->unlisted_since_date, OP_EQ, 1479081645);
  tt_str_op(eg->sampled_by_version, OP_EQ, "1.2.3");
  tt_int_op(eg->currently_listed, OP_EQ, 1);
  tt_i64_op(eg->confirmed_on_date, OP_EQ, 1479081690);
  tt_int_op(eg->confirmed_idx, OP_EQ, 333);
  tt_str_op(eg->extra_state_fields, OP_EQ,
            "and the green grass grew all around rsa_id=all,around");

  tt_int_op(eg->last_tried_to_connect, OP_EQ, 0);
  tt_int_op(eg->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

 done:
  entry_guard_free(eg);
  tor_free(mem_op_hex_tmp);
}

static void
test_entry_guard_parse_from_state_failure(void *arg)
{
  (void)arg;
  entry_guard_t *eg = NULL;

  /* no selection */
  eg = entry_guard_parse_from_state(
                 "rsa_id=596f75206d6179206e656564206120686f626270");
  tt_assert(! eg);

  /* no RSA ID. */
  eg = entry_guard_parse_from_state("in=default nickname=Fred");
  tt_assert(! eg);

  /* Bad RSA ID: bad character. */
  eg = entry_guard_parse_from_state(
                 "in=default "
                 "rsa_id=596f75206d6179206e656564206120686f62627q");
  tt_assert(! eg);

  /* Bad RSA ID: too long.*/
  eg = entry_guard_parse_from_state(
                 "in=default "
                 "rsa_id=596f75206d6179206e656564206120686f6262703");
  tt_assert(! eg);

  /* Bad RSA ID: too short.*/
  eg = entry_guard_parse_from_state(
                 "in=default "
                 "rsa_id=596f75206d6179206e65656420612");
  tt_assert(! eg);

 done:
  entry_guard_free(eg);
}

static void
test_entry_guard_parse_from_state_partial_failure(void *arg)
{
  (void)arg;
  char *mem_op_hex_tmp = NULL;
  entry_guard_t *eg = NULL;
  time_t t = approx_time();

  eg = entry_guard_parse_from_state(
            "in=default "
            "rsa_id=706C75727079666C75727079736C75727079646F "
            "nickname=FredIsANodeWithAStrangeNicknameThatIsTooLong "
            "sampled_on=2016-11-14T00:00:99 "
            "sampled_by=1.2.3 stuff in the middle "
            "unlisted_since=2016-xx-14T00:00:45 "
            "listed=0 "
            "confirmed_on=2016-11-14T00:01:30zz "
            "confirmed_idx=idx "
            "and the green grass grew all around "
            "rsa_id=all,around");
  tt_assert(eg);

  test_mem_op_hex(eg->identity, OP_EQ,
                  "706C75727079666C75727079736C75727079646F");
  tt_str_op(eg->nickname, OP_EQ, "FredIsANodeWithAStrangeNicknameThatIsTooL");
  tt_i64_op(eg->sampled_on_date, OP_EQ, t);
  tt_i64_op(eg->unlisted_since_date, OP_EQ, 0);
  tt_str_op(eg->sampled_by_version, OP_EQ, "1.2.3");
  tt_int_op(eg->currently_listed, OP_EQ, 0);
  tt_i64_op(eg->confirmed_on_date, OP_EQ, 0);
  tt_int_op(eg->confirmed_idx, OP_EQ, -1);
  tt_str_op(eg->extra_state_fields, OP_EQ,
            "stuff in the middle and the green grass grew all around "
            "rsa_id=all,around");

  tt_int_op(eg->last_tried_to_connect, OP_EQ, 0);
  tt_int_op(eg->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

 done:
  entry_guard_free(eg);
  tor_free(mem_op_hex_tmp);
}

static void
test_entry_guard_add_single_guard(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");

  /* 1: Add a single guard to the sample. */
  node_t *n1 = smartlist_get(big_fake_net_nodes, 0);
  time_t now = approx_time();
  tt_assert(n1->is_possible_guard == 1);
  entry_guard_t *g1 = entry_guard_add_to_sample(gs, n1);
  tt_assert(g1);

  /* Make sure its fields look right. */
  tt_mem_op(n1->identity, OP_EQ, g1->identity, DIGEST_LEN);
  tt_i64_op(g1->sampled_on_date, OP_GE, now - 12*86400);
  tt_i64_op(g1->sampled_on_date, OP_LE, now);
  tt_str_op(g1->sampled_by_version, OP_EQ, VERSION);
  tt_assert(g1->currently_listed == 1);
  tt_i64_op(g1->confirmed_on_date, OP_EQ, 0);
  tt_int_op(g1->confirmed_idx, OP_EQ, -1);
  tt_int_op(g1->last_tried_to_connect, OP_EQ, 0);
  tt_uint_op(g1->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);
  tt_i64_op(g1->failing_since, OP_EQ, 0);
  tt_assert(g1->is_filtered_guard == 1);
  tt_assert(g1->is_usable_filtered_guard == 1);
  tt_assert(g1->is_primary == 0);
  tt_assert(g1->extra_state_fields == NULL);

  /* Make sure it got added. */
  tt_int_op(1, OP_EQ, smartlist_len(gs->sampled_entry_guards));
  tt_ptr_op(g1, OP_EQ, smartlist_get(gs->sampled_entry_guards, 0));
  tt_ptr_op(g1, OP_EQ, get_sampled_guard_with_id(gs, (uint8_t*)n1->identity));
  const uint8_t bad_id[20] = {0};
  tt_ptr_op(NULL, OP_EQ, get_sampled_guard_with_id(gs, bad_id));

 done:
  guard_selection_free(gs);
}

static void
test_entry_guard_node_filter(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");
  bridge_line_t *bl = NULL;

  /* Initialize a bunch of node objects that are all guards. */
  const int NUM = 7;
  node_t *n[NUM];
  entry_guard_t *g[NUM];
  int i;
  for (i=0; i < NUM; ++i) {
    n[i] = smartlist_get(big_fake_net_nodes, i*2); // even ones are guards.
    g[i] = entry_guard_add_to_sample(gs, n[i]);

    // everything starts out filtered-in
    tt_assert(g[i]->is_filtered_guard == 1);
    tt_assert(g[i]->is_usable_filtered_guard == 1);
  }
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, NUM);

  /* Make sure refiltering doesn't hurt */
  entry_guards_update_filtered_sets(gs);
  for (i = 0; i < NUM; ++i) {
    tt_assert(g[i]->is_filtered_guard == 1);
    tt_assert(g[i]->is_usable_filtered_guard == 1);
  }
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, NUM);

  /* Now start doing things to make the guards get filtered out, 1 by 1. */

  /* 0: Not listed. */
  g[0]->currently_listed = 0;

  /* 1: path bias says this guard is maybe eeeevil. */
  g[1]->pb.path_bias_disabled = 1;

  /* 2: Unreachable address. */
  n[2]->rs->addr = 0;

  /* 3: ExcludeNodes */
  n[3]->rs->addr = 0x90902020;
  routerset_free(get_options_mutable()->ExcludeNodes);
  get_options_mutable()->ExcludeNodes = routerset_new();
  routerset_parse(get_options_mutable()->ExcludeNodes, "144.144.0.0/16", "");

  /* 4: Bridge. */
  sweep_bridge_list();
  bl = tor_malloc_zero(sizeof(bridge_line_t));
  tor_addr_from_ipv4h(&bl->addr, n[4]->rs->addr);
  bl->port = n[4]->rs->or_port;
  memcpy(bl->digest, n[4]->identity, 20);
  bridge_add_from_config(bl);
  bl = NULL; // prevent free.

  /* 5: Unreachable. This stays in the filter, but isn't in usable-filtered */
  g[5]->last_tried_to_connect = approx_time(); // prevent retry.
  g[5]->is_reachable = GUARD_REACHABLE_NO;

  /* 6: no change. */

  /* Now refilter and inspect. */
  entry_guards_update_filtered_sets(gs);
  for (i = 0; i < NUM; ++i) {
    tt_assert(g[i]->is_filtered_guard == (i == 5 || i == 6));
    tt_assert(g[i]->is_usable_filtered_guard == (i == 6));
  }
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, 1);

 done:
  guard_selection_free(gs);
  tor_free(bl);
}

static void
test_entry_guard_expand_sample(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");
  digestmap_t *node_by_id = digestmap_new();

  entry_guard_t *guard = entry_guards_expand_sample(gs);
  tt_assert(guard); // the last guard returned.

  // Every sampled guard here should be filtered and reachable for now.
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ,
            num_reachable_filtered_guards(gs));

  /* Make sure we got the right number. */
  tt_int_op(MIN_FILTERED_SAMPLE_SIZE, OP_EQ,
            num_reachable_filtered_guards(gs));

  // Make sure everything we got was from our fake node list, and everything
  // was unique.
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, g) {
    const node_t *n = bfn_mock_node_get_by_id(g->identity);
    tt_assert(n);
    tt_ptr_op(NULL, OP_EQ, digestmap_get(node_by_id, g->identity));
    digestmap_set(node_by_id, g->identity, (void*) n);
    int idx = smartlist_pos(big_fake_net_nodes, n);
    // The even ones are the guards; make sure we got guards.
    tt_int_op(idx & 1, OP_EQ, 0);
  } SMARTLIST_FOREACH_END(g);

  // Nothing became unusable/unfiltered, so a subsequent expand should
  // make no changes.
  guard = entry_guards_expand_sample(gs);
  tt_assert(! guard); // no guard was added.
  tt_int_op(MIN_FILTERED_SAMPLE_SIZE, OP_EQ,
            num_reachable_filtered_guards(gs));

  // Make a few guards unreachable.
  guard = smartlist_get(gs->sampled_entry_guards, 0);
  guard->is_usable_filtered_guard = 0;
  guard = smartlist_get(gs->sampled_entry_guards, 1);
  guard->is_usable_filtered_guard = 0;
  guard = smartlist_get(gs->sampled_entry_guards, 2);
  guard->is_usable_filtered_guard = 0;
  tt_int_op(MIN_FILTERED_SAMPLE_SIZE - 3, OP_EQ,
            num_reachable_filtered_guards(gs));

  // This time, expanding the sample will add some more guards.
  guard = entry_guards_expand_sample(gs);
  tt_assert(guard); // no guard was added.
  tt_int_op(MIN_FILTERED_SAMPLE_SIZE, OP_EQ,
            num_reachable_filtered_guards(gs));
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ,
            num_reachable_filtered_guards(gs)+3);

  // Still idempotent.
  guard = entry_guards_expand_sample(gs);
  tt_assert(! guard); // no guard was added.
  tt_int_op(MIN_FILTERED_SAMPLE_SIZE, OP_EQ,
            num_reachable_filtered_guards(gs));

  // Now, do a nasty trick: tell the filter to exclude 31/32 of the guards.
  // This will cause the sample size to get reeeeally huge, while the
  // filtered sample size grows only slowly.
  routerset_free(get_options_mutable()->ExcludeNodes);
  get_options_mutable()->ExcludeNodes = routerset_new();
  routerset_parse(get_options_mutable()->ExcludeNodes, "144.144.0.0/16", "");
  SMARTLIST_FOREACH(big_fake_net_nodes, node_t *, n, {
    if (n_sl_idx % 64 != 0) {
      n->rs->addr = 0x90903030;
    }
  });
  entry_guards_update_filtered_sets(gs);

  // Surely (p ~ 1-2**-60), one of our guards has been excluded.
  tt_int_op(num_reachable_filtered_guards(gs), OP_LT,
            MIN_FILTERED_SAMPLE_SIZE);

  // Try to regenerate the guards.
  guard = entry_guards_expand_sample(gs);
  tt_assert(guard); // no guard was added.

  /* this time, it's possible that we didn't add enough sampled guards. */
  tt_int_op(num_reachable_filtered_guards(gs), OP_LE,
            MIN_FILTERED_SAMPLE_SIZE);
  /* but we definitely didn't exceed the sample maximum. */
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_LE,
            (int)((271 / 2) * .3));

 done:
  guard_selection_free(gs);
  digestmap_free(node_by_id, NULL);
}

static void
test_entry_guard_expand_sample_small_net(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");

  /* Fun corner case: not enough guards to make up our whole sample size. */
  SMARTLIST_FOREACH(big_fake_net_nodes, node_t *, n, {
    if (n_sl_idx >= 40) {
      tor_free(n->rs);
      tor_free(n->md);
      tor_free(n);
      SMARTLIST_DEL_CURRENT(big_fake_net_nodes, n);
    } else {
      n->rs->addr = 0; // make the filter reject this.
    }
  });

  entry_guard_t *guard = entry_guards_expand_sample(gs);
  tt_assert(guard); // the last guard returned -- some guard was added.
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_GT, 0);
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_LT, 10);
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, 0);
 done:
  guard_selection_free(gs);
}

static void
test_entry_guard_update_from_consensus_status(void *arg)
{
  /* Here we're going to have some nodes become un-guardy, and say we got a
   * new consensus. This should cause those nodes to get detected as
   * unreachable. */

  (void)arg;
  int i;
  time_t start = approx_time();
  guard_selection_t *gs = guard_selection_new("default");
  networkstatus_t *ns_tmp = NULL;

  /* Don't randomly backdate stuff; it will make correctness harder to check.*/
  MOCK(randomize_time, mock_randomize_time_no_randomization);

  /* First, sample some guards. */
  entry_guards_expand_sample(gs);
  int n_sampled_pre = smartlist_len(gs->sampled_entry_guards);
  int n_filtered_pre = num_reachable_filtered_guards(gs);
  tt_i64_op(n_sampled_pre, OP_EQ, n_filtered_pre);
  tt_i64_op(n_sampled_pre, OP_GT, 10);

  /* At this point, it should be a no-op to do this: */
  sampled_guards_update_from_consensus(gs);

  /* Now let's make some of our guards become unlisted.  The easiest way to
   * do that would be to take away their guard flag. */
  for (i = 0; i < 5; ++i) {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    n->is_possible_guard = 0;
  }

  update_approx_time(start + 30);
  {
    /* try this with no live networkstatus. Nothing should happen! */
    ns_tmp = dummy_consensus;
    dummy_consensus = NULL;
    sampled_guards_update_from_consensus(gs);
    tt_i64_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_sampled_pre);
    tt_i64_op(num_reachable_filtered_guards(gs), OP_EQ, n_filtered_pre);
    /* put the networkstatus back. */
    dummy_consensus = ns_tmp;
    ns_tmp = NULL;
  }

  /* Now those guards should become unlisted, and drop off the filter, but
   * stay in the sample. */
  update_approx_time(start + 60);
  sampled_guards_update_from_consensus(gs);

  tt_i64_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_sampled_pre);
  tt_i64_op(num_reachable_filtered_guards(gs), OP_EQ, n_filtered_pre - 5);
  for (i = 0; i < 5; ++i) {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    tt_assert(! g->currently_listed);
    tt_i64_op(g->unlisted_since_date, OP_EQ, start+60);
  }
  for (i = 5; i < n_sampled_pre; ++i) {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    tt_assert(g->currently_listed);
    tt_i64_op(g->unlisted_since_date, OP_EQ, 0);
  }

  /* Now re-list one, and remove one completely. */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 0);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    n->is_possible_guard = 1;
  }
  {
    /* try removing the node, to make sure we don't crash on an absent node
     */
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 5);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    smartlist_remove(big_fake_net_nodes, n);
    tor_free(n->rs);
    tor_free(n->md);
    tor_free(n);
  }
  update_approx_time(start + 300);
  sampled_guards_update_from_consensus(gs);

  /* guards 1..5 are now unlisted; 0,6,7.. are listed. */
  tt_i64_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_sampled_pre);
  for (i = 1; i < 6; ++i) {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    tt_assert(! g->currently_listed);
    if (i == 5)
      tt_i64_op(g->unlisted_since_date, OP_EQ, start+300);
    else
      tt_i64_op(g->unlisted_since_date, OP_EQ, start+60);
  }
  for (i = 0; i < n_sampled_pre; i = (!i) ? 6 : i+1) { /* 0,6,7,8, ... */
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    tt_assert(g->currently_listed);
    tt_i64_op(g->unlisted_since_date, OP_EQ, 0);
  }

 done:
  tor_free(ns_tmp); /* in case we couldn't put it back */
  guard_selection_free(gs);
  UNMOCK(randomize_time);
}

static void
test_entry_guard_update_from_consensus_repair(void *arg)
{
  /* Here we'll make sure that our code to repair the unlisted-since
   * times is correct. */

  (void)arg;
  int i;
  time_t start = approx_time();
  guard_selection_t *gs = guard_selection_new("default");

  /* Don't randomly backdate stuff; it will make correctness harder to check.*/
  MOCK(randomize_time, mock_randomize_time_no_randomization);

  /* First, sample some guards. */
  entry_guards_expand_sample(gs);
  int n_sampled_pre = smartlist_len(gs->sampled_entry_guards);
  int n_filtered_pre = num_reachable_filtered_guards(gs);
  tt_i64_op(n_sampled_pre, OP_EQ, n_filtered_pre);
  tt_i64_op(n_sampled_pre, OP_GT, 10);

  /* Now corrupt the list a bit.  Call some unlisted-since-never, and some
   * listed-and-unlisted-since-a-time. */
  update_approx_time(start + 300);
  for (i = 0; i < 3; ++i) {
    /* these will get a date. */
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    n->is_possible_guard = 0;
    g->currently_listed = 0;
  }
  for (i = 3; i < 6; ++i) {
    /* these will become listed. */
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    g->unlisted_since_date = start+100;
  }
  setup_full_capture_of_logs(LOG_WARN);
  sampled_guards_update_from_consensus(gs);
  expect_log_msg_containing(
             "was listed, but with unlisted_since_date set");
  expect_log_msg_containing(
             "was unlisted, but with unlisted_since_date unset");
  teardown_capture_of_logs();

  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_sampled_pre);
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, n_filtered_pre - 3);
  for (i = 3; i < n_sampled_pre; ++i) {
    /* these will become listed. */
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, i);
    if (i < 3) {
      tt_assert(! g->currently_listed);
      tt_i64_op(g->unlisted_since_date, OP_EQ, start+300);
    } else {
      tt_assert(g->currently_listed);
      tt_i64_op(g->unlisted_since_date, OP_EQ, 0);
    }
  }

 done:
  teardown_capture_of_logs();
  guard_selection_free(gs);
  UNMOCK(randomize_time);
}

static void
test_entry_guard_update_from_consensus_remove(void *arg)
{
  /* Now let's check the logic responsible for removing guards from the
   * sample entirely. */

  (void)arg;
  //int i;
  guard_selection_t *gs = guard_selection_new("default");
  smartlist_t *keep_ids = smartlist_new();
  smartlist_t *remove_ids = smartlist_new();

  /* Don't randomly backdate stuff; it will make correctness harder to check.*/
  MOCK(randomize_time, mock_randomize_time_no_randomization);

  /* First, sample some guards. */
  entry_guards_expand_sample(gs);
  int n_sampled_pre = smartlist_len(gs->sampled_entry_guards);
  int n_filtered_pre = num_reachable_filtered_guards(gs);
  tt_i64_op(n_sampled_pre, OP_EQ, n_filtered_pre);
  tt_i64_op(n_sampled_pre, OP_GT, 10);

  const time_t one_day_ago = approx_time() - 1*24*60*60;
  const time_t one_year_ago = approx_time() - 365*24*60*60;
  const time_t two_years_ago = approx_time() - 2*365*24*60*60;
  /* 0: unlisted for a day. (keep this) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 0);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    n->is_possible_guard = 0;
    g->currently_listed = 0;
    g->unlisted_since_date = one_day_ago;
    smartlist_add(keep_ids, tor_memdup(g->identity, 20));
  }
  /* 1: unlisted for a year. (remove this) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 1);
    node_t *n = (node_t*) bfn_mock_node_get_by_id(g->identity);
    n->is_possible_guard = 0;
    g->currently_listed = 0;
    g->unlisted_since_date = one_year_ago;
    smartlist_add(remove_ids, tor_memdup(g->identity, 20));
  }
  /* 2: added a day ago, never confirmed. (keep this) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 2);
    g->sampled_on_date = one_day_ago;
    smartlist_add(keep_ids, tor_memdup(g->identity, 20));
  }
  /* 3: added a year ago, never confirmed. (remove this) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 3);
    g->sampled_on_date = one_year_ago;
    smartlist_add(remove_ids, tor_memdup(g->identity, 20));
  }
  /* 4: added two year ago, confirmed yesterday, primary. (keep this.) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 4);
    g->sampled_on_date = one_year_ago;
    g->confirmed_on_date = one_day_ago;
    g->confirmed_idx = 0;
    g->is_primary = 1;
    smartlist_add(gs->confirmed_entry_guards, g);
    smartlist_add(gs->primary_entry_guards, g);
    smartlist_add(keep_ids, tor_memdup(g->identity, 20));
  }
  /* 5: added two years ago, confirmed a year ago, primary. (remove this) */
  {
    entry_guard_t *g = smartlist_get(gs->sampled_entry_guards, 5);
    g->sampled_on_date = two_years_ago;
    g->confirmed_on_date = one_year_ago;
    g->confirmed_idx = 1;
    g->is_primary = 1;
    smartlist_add(gs->confirmed_entry_guards, g);
    smartlist_add(gs->primary_entry_guards, g);
    smartlist_add(remove_ids, tor_memdup(g->identity, 20));
  }

  sampled_guards_update_from_consensus(gs);

  /* Did we remove the right ones? */
  SMARTLIST_FOREACH(keep_ids, uint8_t *, id, {
      tt_assert(get_sampled_guard_with_id(gs, id) != NULL);
  });
  SMARTLIST_FOREACH(remove_ids, uint8_t *, id, {
    tt_want(get_sampled_guard_with_id(gs, id) == NULL);
  });

  /* Did we remove the right number? */
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_sampled_pre - 3);

 done:
  guard_selection_free(gs);
  UNMOCK(randomize_time);
  SMARTLIST_FOREACH(keep_ids, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(remove_ids, char *, cp, tor_free(cp));
  smartlist_free(keep_ids);
  smartlist_free(remove_ids);
}

static void
test_entry_guard_confirming_guards(void *arg)
{
  (void)arg;
  /* Now let's check the logic responsible for manipulating the list
   * of confirmed guards */
  guard_selection_t *gs = guard_selection_new("default");
  MOCK(randomize_time, mock_randomize_time_no_randomization);

  /* Create the sample. */
  entry_guards_expand_sample(gs);

  /* Confirm a few  guards. */
  time_t start = approx_time();
  entry_guard_t *g1 = smartlist_get(gs->sampled_entry_guards, 0);
  entry_guard_t *g2 = smartlist_get(gs->sampled_entry_guards, 1);
  entry_guard_t *g3 = smartlist_get(gs->sampled_entry_guards, 8);
  make_guard_confirmed(gs, g2);
  update_approx_time(start + 10);
  make_guard_confirmed(gs, g1);
  make_guard_confirmed(gs, g3);

  /* Were the correct dates and indices fed in? */
  tt_int_op(g1->confirmed_idx, OP_EQ, 1);
  tt_int_op(g2->confirmed_idx, OP_EQ, 0);
  tt_int_op(g3->confirmed_idx, OP_EQ, 2);
  tt_i64_op(g1->confirmed_on_date, OP_EQ, start+10);
  tt_i64_op(g2->confirmed_on_date, OP_EQ, start);
  tt_i64_op(g3->confirmed_on_date, OP_EQ, start+10);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 0), OP_EQ, g2);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 1), OP_EQ, g1);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 2), OP_EQ, g3);

  /* Now make sure we can regenerate the confirmed_entry_guards list. */
  smartlist_clear(gs->confirmed_entry_guards);
  g2->confirmed_idx = 0;
  g1->confirmed_idx = 10;
  g3->confirmed_idx = 100;
  entry_guards_update_confirmed(gs);
  tt_int_op(g1->confirmed_idx, OP_EQ, 1);
  tt_int_op(g2->confirmed_idx, OP_EQ, 0);
  tt_int_op(g3->confirmed_idx, OP_EQ, 2);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 0), OP_EQ, g2);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 1), OP_EQ, g1);
  tt_ptr_op(smartlist_get(gs->confirmed_entry_guards, 2), OP_EQ, g3);

  /* Now make sure we can regenerate the confirmed_entry_guards list if
   * the indices are messed up. */
  g1->confirmed_idx = g2->confirmed_idx = g3->confirmed_idx = 999;
  smartlist_clear(gs->confirmed_entry_guards);
  entry_guards_update_confirmed(gs);
  tt_int_op(g1->confirmed_idx, OP_GE, 0);
  tt_int_op(g2->confirmed_idx, OP_GE, 0);
  tt_int_op(g3->confirmed_idx, OP_GE, 0);
  tt_int_op(g1->confirmed_idx, OP_LE, 2);
  tt_int_op(g2->confirmed_idx, OP_LE, 2);
  tt_int_op(g3->confirmed_idx, OP_LE, 2);
  g1 = smartlist_get(gs->confirmed_entry_guards, 0);
  g2 = smartlist_get(gs->confirmed_entry_guards, 1);
  g3 = smartlist_get(gs->confirmed_entry_guards, 2);
  tt_int_op(g1->confirmed_idx, OP_EQ, 0);
  tt_int_op(g2->confirmed_idx, OP_EQ, 1);
  tt_int_op(g3->confirmed_idx, OP_EQ, 2);
  tt_assert(g1 != g2);
  tt_assert(g1 != g3);
  tt_assert(g2 != g3);

 done:
  UNMOCK(randomize_time);
  guard_selection_free(gs);
}

static void
test_entry_guard_sample_reachable_filtered(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");
  entry_guards_expand_sample(gs);
  const int N = 10000;
  bitarray_t *selected = NULL;
  int i, j;

  /* We've got a sampled list now; let's make one non-usable-filtered; some
   * confirmed, some primary, some pending.
   */
  int n_guards = smartlist_len(gs->sampled_entry_guards);
  tt_int_op(n_guards, OP_GT, 10);
  entry_guard_t *g;
  g = smartlist_get(gs->sampled_entry_guards, 0);
  g->is_pending = 1;
  g = smartlist_get(gs->sampled_entry_guards, 1);
  make_guard_confirmed(gs, g);
  g = smartlist_get(gs->sampled_entry_guards, 2);
  g->is_primary = 1;
  g = smartlist_get(gs->sampled_entry_guards, 3);
  g->pb.path_bias_disabled = 1;

  entry_guards_update_filtered_sets(gs);
  gs->primary_guards_up_to_date = 1;
  tt_int_op(num_reachable_filtered_guards(gs), OP_EQ, n_guards - 1);
  tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_guards);

  // +1 since the one we made disabled will make  another one get added.
  ++n_guards;

  /* Try a bunch of selections. */
  const struct {
    int flag; int idx;
  } tests[] = {
    { 0, -1 },
    { SAMPLE_EXCLUDE_CONFIRMED, 1 },
    { SAMPLE_EXCLUDE_PRIMARY|SAMPLE_NO_UPDATE_PRIMARY, 2 },
    { SAMPLE_EXCLUDE_PENDING, 0 },
    { -1, -1},
  };

  for (j = 0; tests[j].flag >= 0; ++j) {
    selected = bitarray_init_zero(n_guards);
    const int excluded_flags = tests[j].flag;
    const int excluded_idx = tests[j].idx;
    for (i = 0; i < N; ++i) {
      g = sample_reachable_filtered_entry_guards(gs, excluded_flags);
      tor_assert(g);
      int pos = smartlist_pos(gs->sampled_entry_guards, g);
      tt_int_op(smartlist_len(gs->sampled_entry_guards), OP_EQ, n_guards);
      tt_int_op(pos, OP_GE, 0);
      tt_int_op(pos, OP_LT, n_guards);
      bitarray_set(selected, pos);
    }
    for (i = 0; i < n_guards; ++i) {
      const int should_be_set = (i != excluded_idx &&
                                 i != 3); // filtered out.
      tt_int_op(!!bitarray_is_set(selected, i), OP_EQ, should_be_set);
    }
    bitarray_free(selected);
    selected = NULL;
  }

 done:
  guard_selection_free(gs);
  bitarray_free(selected);
}

static void
test_entry_guard_sample_reachable_filtered_empty(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");
  /* What if we try to sample from a set of 0? */
  SMARTLIST_FOREACH(big_fake_net_nodes, node_t *, n,
                    n->is_possible_guard = 0);

  entry_guard_t *g = sample_reachable_filtered_entry_guards(gs, 0);
  tt_ptr_op(g, OP_EQ, NULL);

 done:
  guard_selection_free(gs);
}

static void
test_entry_guard_retry_unreachable(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");

  entry_guards_expand_sample(gs);
  /* Let's say that we have two guards, and they're down.
   */
  time_t start = approx_time();;
  entry_guard_t *g1 = smartlist_get(gs->sampled_entry_guards, 0);
  entry_guard_t *g2 = smartlist_get(gs->sampled_entry_guards, 1);
  entry_guard_t *g3 = smartlist_get(gs->sampled_entry_guards, 2);
  g1->is_reachable = GUARD_REACHABLE_NO;
  g2->is_reachable = GUARD_REACHABLE_NO;
  g1->is_primary = 1;
  g1->failing_since = g2->failing_since = start;
  g1->last_tried_to_connect = g2->last_tried_to_connect = start;

  /* Wait 5 minutes.  Nothing will get retried. */
  update_approx_time(start + 5 * 60);
  entry_guard_consider_retry(g1);
  entry_guard_consider_retry(g2);
  entry_guard_consider_retry(g3); // just to make sure this doesn't crash.
  tt_int_op(g1->is_reachable, OP_EQ, GUARD_REACHABLE_NO);
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_NO);
  tt_int_op(g3->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

  /* After 30 min, the primary one gets retried */
  update_approx_time(start + 35 * 60);
  entry_guard_consider_retry(g1);
  entry_guard_consider_retry(g2);
  tt_int_op(g1->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_NO);

  g1->is_reachable = GUARD_REACHABLE_NO;
  g1->last_tried_to_connect = start + 35*60;

  /* After 1 hour, we'll retry the nonprimary one. */
  update_approx_time(start + 61 * 60);
  entry_guard_consider_retry(g1);
  entry_guard_consider_retry(g2);
  tt_int_op(g1->is_reachable, OP_EQ, GUARD_REACHABLE_NO);
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

  g2->is_reachable = GUARD_REACHABLE_NO;
  g2->last_tried_to_connect = start + 61*60;

  /* And then the primary one again. */
  update_approx_time(start + 66 * 60);
  entry_guard_consider_retry(g1);
  entry_guard_consider_retry(g2);
  tt_int_op(g1->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_NO);

 done:
  guard_selection_free(gs);
}

static void
test_entry_guard_manage_primary(void *arg)
{
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");
  smartlist_t *prev_guards = smartlist_new();

  /* If no guards are confirmed, we should pick a few reachable guards and
   * call them all primary. But not confirmed.*/
  entry_guards_update_primary(gs);
  int n_primary = smartlist_len(gs->primary_entry_guards);
  tt_int_op(n_primary, OP_GE, 1);
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, g, {
    tt_assert(g->is_primary);
    tt_assert(g->confirmed_idx == -1);
  });

  /* Calling it a second time should leave the guards unchanged. */
  smartlist_add_all(prev_guards, gs->primary_entry_guards);
  entry_guards_update_primary(gs);
  tt_int_op(smartlist_len(gs->primary_entry_guards), OP_EQ, n_primary);
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, g, {
    tt_ptr_op(g, OP_EQ, smartlist_get(prev_guards, g_sl_idx));
  });

  /* If we have one confirmed guard, that guards becomes the first primary
   * guard, and the other primary guards get kept. */

  /* find a non-primary guard... */
  entry_guard_t *confirmed = NULL;
  SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, g, {
    if (! g->is_primary) {
      confirmed = g;
      break;
    }
  });
  tt_assert(confirmed);
  /* make it confirmed. */
  make_guard_confirmed(gs, confirmed);
  /* update the list... */
  smartlist_clear(prev_guards);
  smartlist_add_all(prev_guards, gs->primary_entry_guards);
  entry_guards_update_primary(gs);

  /*  and see what's primary now! */
  tt_int_op(smartlist_len(gs->primary_entry_guards), OP_EQ, n_primary);
  tt_ptr_op(smartlist_get(gs->primary_entry_guards, 0), OP_EQ, confirmed);
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, g, {
    tt_assert(g->is_primary);
    if (g_sl_idx == 0)
      continue;
    tt_ptr_op(g, OP_EQ, smartlist_get(prev_guards, g_sl_idx - 1));
  });
  {
    entry_guard_t *prev_last_guard = smartlist_get(prev_guards, n_primary-1);
    tt_assert(! prev_last_guard->is_primary);
  }

  /* Calling it a fourth time should leave the guards unchanged. */
  smartlist_clear(prev_guards);
  smartlist_add_all(prev_guards, gs->primary_entry_guards);
  entry_guards_update_primary(gs);
  tt_int_op(smartlist_len(gs->primary_entry_guards), OP_EQ, n_primary);
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, g, {
    tt_ptr_op(g, OP_EQ, smartlist_get(prev_guards, g_sl_idx));
  });

 done:
  guard_selection_free(gs);
  smartlist_free(prev_guards);
}

static void
test_entry_guard_select_for_circuit_no_confirmed(void *arg)
{
  /* Simpler cases: no gaurds are confirmed yet. */
  (void)arg;
  guard_selection_t *gs = guard_selection_new("default");

  /* simple starting configuration */
  entry_guards_update_primary(gs);
  unsigned state = 9999;

  entry_guard_t *g = select_entry_guard_for_circuit(gs, &state);

  tt_assert(g);
  tt_assert(g->is_primary);
  tt_int_op(g->confirmed_idx, OP_EQ, -1);
  tt_assert(g->is_pending == 0); // primary implies non-pending.
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_ON_COMPLETION);
  tt_i64_op(g->last_tried_to_connect, OP_EQ, approx_time());

  // If we do that again, we should get the same guard.
  entry_guard_t *g2 = select_entry_guard_for_circuit(gs, &state);
  tt_ptr_op(g2, OP_EQ, g);

  // if we mark that guard down, we should get a different primary guard.
  // auto-retry it.
  g->is_reachable = GUARD_REACHABLE_NO;
  g->unreachable_since = approx_time() - 10;
  g->last_tried_to_connect = approx_time() - 10;
  state = 9999;
  g2 = select_entry_guard_for_circuit(gs, &state);
  tt_ptr_op(g2, OP_NE, g);
  tt_assert(g2);
  tt_assert(g2->is_primary);
  tt_int_op(g2->confirmed_idx, OP_EQ, -1);
  tt_assert(g2->is_pending == 0); // primary implies non-pending.
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_ON_COMPLETION);
  tt_i64_op(g2->last_tried_to_connect, OP_EQ, approx_time());

  // If we say that the first primary guard was last tried a long time ago, we
  // should get an automatic retry on it.
  g->unreachable_since = approx_time() - 72*60*60;
  g->last_tried_to_connect = approx_time() - 72*60*60;
  state = 9999;
  g2 = select_entry_guard_for_circuit(gs, &state);
  tt_ptr_op(g2, OP_EQ, g);
  tt_assert(g2);
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_ON_COMPLETION);
  tt_i64_op(g2->last_tried_to_connect, OP_EQ, approx_time());
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

  // And if we mark ALL the primary guards down, we should get another guard
  // at random.
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, guard, {
    guard->is_reachable = GUARD_REACHABLE_NO;
    guard->last_tried_to_connect = approx_time() - 5;
    guard->unreachable_since = approx_time() - 30;
  });
  state = 9999;
  g2 = select_entry_guard_for_circuit(gs, &state);
  tt_assert(g2);
  tt_assert(!g2->is_primary);
  tt_int_op(g2->confirmed_idx, OP_EQ, -1);
  tt_assert(g2->is_pending == 1);
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD);
  tt_i64_op(g2->last_tried_to_connect, OP_EQ, approx_time());
  tt_int_op(g2->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);

  // As a bonus, maybe we should be retrying the primary guards. Let's say so.
  mark_primary_guards_maybe_reachable(gs);
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, guard, {
    tt_int_op(guard->is_reachable, OP_EQ, GUARD_REACHABLE_MAYBE);
    tt_assert(guard->is_usable_filtered_guard == 1);
    // no change to these fields.
    tt_i64_op(guard->last_tried_to_connect, OP_EQ, approx_time() - 5);
    tt_i64_op(guard->unreachable_since, OP_EQ, approx_time() - 30);
  });

 done:
  guard_selection_free(gs);
}

static void
test_entry_guard_select_for_circuit_confirmed(void *arg)
{
  /* Case 2: if all the primary guards are down, and there are more confirmed
     guards, we use a confirmed guard. */
  (void)arg;
  int i;
  guard_selection_t *gs = guard_selection_new("default");
  const int N_CONFIRMED = 10;

  /* slightly more complicated simple starting configuration */
  entry_guards_update_primary(gs);
  for (i = 0; i < N_CONFIRMED; ++i) {
    entry_guard_t *guard = smartlist_get(gs->sampled_entry_guards, i);
    make_guard_confirmed(gs, guard);
  }
  entry_guards_update_primary(gs); // rebuild the primary list.

  unsigned state = 9999;

  // As above, this gives us a primary guard.
  entry_guard_t *g = select_entry_guard_for_circuit(gs, &state);
  tt_assert(g);
  tt_assert(g->is_primary);
  tt_int_op(g->confirmed_idx, OP_EQ, 0);
  tt_assert(g->is_pending == 0); // primary implies non-pending.
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_ON_COMPLETION);
  tt_i64_op(g->last_tried_to_connect, OP_EQ, approx_time());
  tt_ptr_op(g, OP_EQ, smartlist_get(gs->primary_entry_guards, 0));

  // But if we mark all the primary guards down...
  SMARTLIST_FOREACH(gs->primary_entry_guards, entry_guard_t *, guard, {
    guard->last_tried_to_connect = approx_time();
    entry_guards_note_guard_failure(gs, guard);
  });

  // ... we should get a confirmed guard.
  state = 9999;
  g = select_entry_guard_for_circuit(gs, &state);
  tt_assert(g);
  tt_assert(! g->is_primary);
  tt_int_op(g->confirmed_idx, OP_EQ, smartlist_len(gs->primary_entry_guards));
  tt_assert(g->is_pending);
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD);
  tt_i64_op(g->last_tried_to_connect, OP_EQ, approx_time());

  // And if we try again, we should get a different confirmed guard, since
  // that one is pending.
  state = 9999;
  entry_guard_t *g2 = select_entry_guard_for_circuit(gs, &state);
  tt_assert(g2);
  tt_assert(! g2->is_primary);
  tt_ptr_op(g2, OP_NE, g);
  tt_int_op(g2->confirmed_idx, OP_EQ,
            smartlist_len(gs->primary_entry_guards)+1);
  tt_assert(g2->is_pending);
  tt_uint_op(state, OP_EQ, GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD);
  tt_i64_op(g2->last_tried_to_connect, OP_EQ, approx_time());

  // If we make every confirmed guard become pending then we start poking
  // other guards.
  const int n_remaining_confirmed =
    N_CONFIRMED - 2 - smartlist_len(gs->primary_entry_guards);
  for (i = 0; i < n_remaining_confirmed; ++i) {
    g = select_entry_guard_for_circuit(gs, &state);
    tt_int_op(g->confirmed_idx, OP_GE, 0);
    tt_assert(g);
  }
  state = 9999;
  g = select_entry_guard_for_circuit(gs, &state);
  tt_assert(g);
  tt_assert(g->is_pending);
  tt_int_op(g->confirmed_idx, OP_EQ, -1);

 done:
  guard_selection_free(gs);
}

static const struct testcase_setup_t fake_network = {
  fake_network_setup, fake_network_cleanup
};

static const struct testcase_setup_t big_fake_network = {
  big_fake_network_setup, big_fake_network_cleanup
};

#define BFN_TEST(name) \
  { #name, test_entry_guard_ ## name, TT_FORK, &big_fake_network, NULL }

struct testcase_t entrynodes_tests[] = {
  { "entry_is_time_to_retry", test_entry_is_time_to_retry,
    TT_FORK, NULL, NULL },
  { "choose_random_entry_no_guards", test_choose_random_entry_no_guards,
    TT_FORK, &fake_network, NULL },
  { "choose_random_entry_one_possible_guard",
    test_choose_random_entry_one_possible_guard,
    TT_FORK, &fake_network, NULL },
  { "populate_live_entry_guards_1guard",
    test_populate_live_entry_guards_1guard,
    TT_FORK, &fake_network, NULL },
  { "populate_live_entry_guards_3guards",
    test_populate_live_entry_guards_3guards,
    TT_FORK, &fake_network, NULL },
  { "entry_guards_parse_state_simple",
    test_entry_guards_parse_state_simple,
    TT_FORK, &fake_network, NULL },
  { "entry_guards_parse_state_pathbias",
    test_entry_guards_parse_state_pathbias,
    TT_FORK, &fake_network, NULL },
  { "entry_guards_set_from_config",
    test_entry_guards_set_from_config,
    TT_FORK, &fake_network, NULL },
  { "entry_is_live",
    test_entry_is_live,
    TT_FORK, &fake_network, NULL },
  { "node_preferred_orport",
    test_node_preferred_orport,
    0, NULL, NULL },
  { "entry_guard_describe", test_entry_guard_describe, 0, NULL, NULL },
  { "randomize_time", test_entry_guard_randomize_time, 0, NULL, NULL },
  { "encode_for_state_minimal",
    test_entry_guard_encode_for_state_minimal, 0, NULL, NULL },
  { "encode_for_state_maximal",
    test_entry_guard_encode_for_state_maximal, 0, NULL, NULL },
  { "parse_from_state_minimal",
    test_entry_guard_parse_from_state_minimal, 0, NULL, NULL },
  { "parse_from_state_maximal",
    test_entry_guard_parse_from_state_maximal, 0, NULL, NULL },
  { "parse_from_state_failure",
    test_entry_guard_parse_from_state_failure, 0, NULL, NULL },
  { "parse_from_state_partial_failure",
    test_entry_guard_parse_from_state_partial_failure, 0, NULL, NULL },
  BFN_TEST(add_single_guard),
  BFN_TEST(node_filter),
  BFN_TEST(expand_sample),
  BFN_TEST(expand_sample_small_net),
  BFN_TEST(update_from_consensus_status),
  BFN_TEST(update_from_consensus_repair),
  BFN_TEST(update_from_consensus_remove),
  BFN_TEST(confirming_guards),
  BFN_TEST(sample_reachable_filtered),
  BFN_TEST(sample_reachable_filtered_empty),
  BFN_TEST(retry_unreachable),
  BFN_TEST(manage_primary),
  BFN_TEST(select_for_circuit_no_confirmed),
  BFN_TEST(select_for_circuit_confirmed),
  END_OF_TESTCASES
};

