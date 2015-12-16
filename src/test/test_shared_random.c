#define SHARED_RANDOM_PRIVATE
#define SHARED_RANDOM_STATE_PRIVATE
#define CONFIG_PRIVATE

#include "or.h"
#include "test.h"
#include "config.h"
#include "shared-random.h"
#include "shared-random-state.h"
#include "routerkeys.h"
#include "routerlist.h"
#include "router.h"
#include "routerparse.h"
#include "networkstatus.h"

static void
test_get_sr_protocol_phase(void *arg)
{
  time_t the_time;
  sr_phase_t phase;
  int retval;

  (void) arg;

  /* Initialize SR state */
  retval = sr_init(0);
  tt_int_op(retval, ==, 0);

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 23:59:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 00:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 00:00:01 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 11:59:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 12:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 12:00:01 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 13:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

 done:
  ;
}

static void
test_get_state_valid_until_time(void *arg)
{
  time_t current_time;
  time_t valid_until_time;
  char tbuf[ISO_TIME_LEN + 1];
  int retval;

  (void) arg;

  {
    /* Get the valid until time if called at 00:00:01 */
    retval = parse_rfc1123_time("Mon, 20 Apr 2015 00:00:01 UTC", &current_time);
    tt_int_op(retval, ==, 0);
    valid_until_time = get_state_valid_until_time(current_time);

    /* Compare it with the correct result */
    format_iso_time(tbuf, valid_until_time);
    tt_str_op("2015-04-21 00:00:00", OP_EQ, tbuf);
  }

  {
    retval = parse_rfc1123_time("Mon, 20 Apr 2015 19:22:00 UTC", &current_time);
    tt_int_op(retval, ==, 0);
    valid_until_time = get_state_valid_until_time(current_time);

    format_iso_time(tbuf, valid_until_time);
    tt_str_op("2015-04-21 00:00:00", OP_EQ, tbuf);
  }

  {
    retval = parse_rfc1123_time("Mon, 20 Apr 2015 23:59:00 UTC", &current_time);
    tt_int_op(retval, ==, 0);
    valid_until_time = get_state_valid_until_time(current_time);

    format_iso_time(tbuf, valid_until_time);
    tt_str_op("2015-04-21 00:00:00", OP_EQ, tbuf);
  }

  {
    retval = parse_rfc1123_time("Mon, 20 Apr 2015 00:00:00 UTC", &current_time);
    tt_int_op(retval, ==, 0);
    valid_until_time = get_state_valid_until_time(current_time);

    format_iso_time(tbuf, valid_until_time);
    tt_str_op("2015-04-21 00:00:00", OP_EQ, tbuf);
  }

 done:
  ;
}

extern const char AUTHORITY_CERT_1[];

/* In this test we are going to generate a sr_commit_t object and validate
 * it. We first generate our values, and then we parse them as if they were
 * received from the network. After we parse both the commit and the reveal,
 * we verify that they indeed match. */
static void
test_sr_commit(void *arg)
{
  authority_cert_t *auth_cert = NULL;
  time_t now = time(NULL);
  sr_commit_t *our_commit = NULL;
  smartlist_t *args = smartlist_new();

  (void) arg;

  {  /* Setup a minimal dirauth environment for this test  */
    or_options_t *options = get_options_mutable();

    auth_cert = authority_cert_parse_from_string(AUTHORITY_CERT_1, NULL);
    tt_assert(auth_cert);

    options->AuthoritativeDir = 1;
    tt_int_op(0, ==, load_ed_keys(options, now));
  }

  /* Generate our commit object and validate it has the appropriate field
   * that we can then use to build a representation that we'll find in a
   * vote coming from the network. */
  {
    sr_commit_t test_commit;
    our_commit = sr_generate_our_commitment(now, auth_cert);
    tt_assert(our_commit);
    /* Default and only supported algorithm for now. */
    tt_assert(our_commit->alg == DIGEST_SHA256);
    /* We should have a reveal value. */
    tt_assert(commit_has_reveal_value(our_commit));
    /* We should have a random value. */
    tt_assert(!tor_mem_is_zero(our_commit->random_number,
                               sizeof(our_commit->random_number)));
    /* Commit and reveal timestamp should be the same. */
    tt_int_op(our_commit->commit_ts, ==, our_commit->reveal_ts);
    /* We should have a hashed reveal. */
    tt_assert(!tor_mem_is_zero(our_commit->hashed_reveal,
                               sizeof(our_commit->hashed_reveal)));
    /* Do we have a valid encoded commit and reveal. Note the following only
     * tests if the generated values are correct. Their could be a bug in
     * the decode function but we test them seperately. */
    tt_int_op(0, ==, reveal_decode(our_commit->encoded_reveal,
                                   &test_commit));
    tt_int_op(0, ==, commit_decode(our_commit->encoded_commit,
                                   &test_commit));
    tt_int_op(0, ==, verify_commit_and_reveal(our_commit));
  }

  /* We'll build a list of values from our commit that our parsing function
   * takes from a vote line and see if we can parse it correctly. */
  {
    sr_commit_t *parsed_commit;
    smartlist_add(args,
                  tor_strdup(crypto_digest_algorithm_get_name(our_commit->alg)));
    smartlist_add(args, our_commit->auth_fingerprint);
    smartlist_add(args, our_commit->rsa_identity_fpr);
    smartlist_add(args, our_commit->encoded_commit);
    smartlist_add(args, our_commit->encoded_reveal);
    parsed_commit = sr_parse_commit(args);
    tt_assert(parsed_commit);
    /* That parsed commit should be _EXACTLY_ like our original commit. */
    tt_mem_op(parsed_commit, OP_EQ, our_commit, sizeof(*parsed_commit));
    /* Cleanup */
    tor_free(smartlist_get(args, 0)); /* strdup here. */
    smartlist_clear(args);
    sr_commit_free(parsed_commit);
  }

 done:
  smartlist_free(args);
  sr_commit_free(our_commit);
}

/* Test the encoding and decoding function for commit and reveal values. */
static void
test_encoding(void *arg)
{
  (void) arg;
  int ret, duper_rand = 42;
  /* Random number is 32 bytes. */
  char raw_rand[32];
  uint64_t ts = 1449159312;
  char hashed_rand[DIGEST256_LEN], hashed_reveal[DIGEST256_LEN];
  sr_commit_t parsed_commit;

  /* Encoded commit is: base64-encode( H(H(42)) || 1449159312). Remember
   * that we do no expose the raw bytes of our PRNG to the network thus
   * explaining the double H(). */
  static const char *encoded_commit =
    "VnpHIJFkjNo+AEQGwCA5mnTu0/XXN5WRRQte3+GtK/oAAAAAVmBqkA==";
  /* Encoded reveal is: base64-encode( H(42) || 1449159312). */
  static const char *encoded_reveal =
    "AAAAAFZgapAS87tMUHatqR+rOln543nqMA+98YfuQEkicHgAbDlXQQ==";

  /* Set up our raw random bytes array. */
  memset(raw_rand, 0, sizeof(raw_rand));
  memcpy(raw_rand, &duper_rand, sizeof(duper_rand));
  /* Hash random number. */
  ret = crypto_digest256(hashed_rand, raw_rand, sizeof(raw_rand),
                         DIGEST_SHA256);
  tt_int_op(0, ==, ret);
  /* Hash reveal value. */
  tt_int_op(SR_REVEAL_BASE64_LEN, ==, strlen(encoded_reveal));
  ret = crypto_digest256(hashed_reveal, encoded_reveal,
                         strlen(encoded_reveal), DIGEST_SHA256);
  tt_int_op(0, ==, ret);
  tt_int_op(SR_COMMIT_BASE64_LEN, ==, strlen(encoded_commit));

  /* Test our commit/reveal decode functions. */
  {
    /* Test the reveal encoded value. */
    tt_int_op(0, ==, reveal_decode(encoded_reveal, &parsed_commit));
    tt_uint_op(ts, ==, parsed_commit.reveal_ts);
    tt_mem_op(hashed_rand, OP_EQ, parsed_commit.random_number,
              sizeof(hashed_rand));

    /* Test the commit encoded value. */
    memset(&parsed_commit, 0, sizeof(parsed_commit));
    tt_int_op(0, ==, commit_decode(encoded_commit, &parsed_commit));
    tt_uint_op(ts, ==, parsed_commit.commit_ts);
    tt_mem_op(encoded_commit, OP_EQ, parsed_commit.encoded_commit,
              sizeof(parsed_commit.encoded_commit));
    tt_mem_op(hashed_reveal, OP_EQ, parsed_commit.hashed_reveal,
              sizeof(hashed_reveal));
  }

  /* Test our commit/reveal encode functions. */
  {
    /* Test the reveal encode. */
    char encoded[SR_REVEAL_BASE64_LEN + 1];
    parsed_commit.commit_ts = ts;
    memcpy(parsed_commit.random_number, hashed_rand,
           sizeof(parsed_commit.random_number));
    ret = reveal_encode(&parsed_commit, encoded, sizeof(encoded));
    tt_int_op(SR_REVEAL_BASE64_LEN, ==, ret);
    tt_mem_op(encoded_reveal, OP_EQ, encoded, strlen(encoded_reveal));
  }

  {
    /* Test the commit encode. */
    char encoded[SR_COMMIT_BASE64_LEN + 1];
    parsed_commit.commit_ts = ts;
    memcpy(parsed_commit.hashed_reveal, hashed_reveal,
           sizeof(parsed_commit.hashed_reveal));
    ret = commit_encode(&parsed_commit, encoded, sizeof(encoded));
    tt_int_op(SR_COMMIT_BASE64_LEN, ==, ret);
    tt_mem_op(encoded_commit, OP_EQ, encoded, strlen(encoded_commit));
  }

 done:
  ;
}

/* Test anything that has to do with SR protocol and vote. */
static void
test_vote(void *arg)
{
  int ret;
  authority_cert_t *auth_cert = NULL;
  time_t now = time(NULL);
  sr_commit_t *our_commit = NULL;

  (void) arg;

  {  /* Setup a minimal dirauth environment for this test  */
    or_options_t *options = get_options_mutable();

    auth_cert = authority_cert_parse_from_string(AUTHORITY_CERT_1, NULL);
    tt_assert(auth_cert);

    options->AuthoritativeDir = 1;
    tt_int_op(0, ==, load_ed_keys(options, now));

    sr_state_init(0);
    /* Set ourself in reveal phase so we can parse the reveal value in the
     * vote as well. */
    set_sr_phase(SR_PHASE_REVEAL);
  }

  /* Generate our commit object and validate it has the appropriate field
   * that we can then use to build a representation that we'll find in a
   * vote coming from the network. */
  {
    sr_commit_t *saved_commit;
    our_commit = sr_generate_our_commitment(now, auth_cert);
    tt_assert(our_commit);
    sr_state_add_commit(our_commit);
    /* Make sure it's there. */
    saved_commit = sr_state_get_commit_by_rsa(our_commit->rsa_identity_fpr);
    tt_assert(saved_commit);
  }

  {
    smartlist_t *chunks = smartlist_new();
    smartlist_t *tokens = smartlist_new();
    /* Get our vote line and validate it. */
    char *lines = sr_get_string_for_vote();
    tt_assert(lines);
    /* Split the lines. We expect 2 here. */
    ret = smartlist_split_string(chunks, lines, "\n", SPLIT_IGNORE_BLANK, 0);
    tt_int_op(ret, ==, 2);
    tt_str_op(smartlist_get(chunks, 0), OP_EQ, "shared-rand-participate");
    /* Get our commitment line and will validate it agains our commit. The
     * format is as follow:
     *    "shared-rand-commitment" SP identity SP algname SP COMMIT [SP REVEAL] NL
     */
    char *commit_line = smartlist_get(chunks, 1);
    tt_assert(commit_line);
    ret = smartlist_split_string(tokens, commit_line, " ", 0, 0);
    tt_int_op(ret, ==, 5);
    tt_str_op(smartlist_get(tokens, 0), OP_EQ, "shared-rand-commitment");
    tt_str_op(smartlist_get(tokens, 1), OP_EQ,
              our_commit->auth_fingerprint);
    tt_str_op(smartlist_get(tokens, 2), OP_EQ,
              crypto_digest_algorithm_get_name(DIGEST_SHA256));
    tt_str_op(smartlist_get(tokens, 3), OP_EQ, our_commit->encoded_commit);
    tt_str_op(smartlist_get(tokens, 4), OP_EQ, our_commit->encoded_reveal);

    /* Finally, does this vote line creates a valid commit object? */
    smartlist_t *args = smartlist_new();
    smartlist_add(args, smartlist_get(tokens, 2));
    smartlist_add(args, smartlist_get(tokens, 1));
    smartlist_add(args, our_commit->rsa_identity_fpr);
    smartlist_add(args, smartlist_get(tokens, 3));
    smartlist_add(args, smartlist_get(tokens, 4));
    sr_commit_t *parsed_commit = sr_parse_commit(args);
    tt_assert(parsed_commit);
    tt_mem_op(parsed_commit, ==, our_commit, sizeof(*our_commit));

    /* Clean up */
    sr_commit_free(parsed_commit);
    SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
    smartlist_free(chunks);
    SMARTLIST_FOREACH(tokens, char *, s, tor_free(s));
    smartlist_free(tokens);
    smartlist_clear(args);
    smartlist_free(args);
  }

 done:
  sr_commit_free(our_commit);
}

const char *sr_state_str = "Version 1\n"
  "ValidUntil 2666-04-20 07:16:00\n"
  "Commitment sha256 RkoaSeZBiyJs23P6aOLEyUsumWwjWYnA+DQm1IaKXu8 FA3CEC2C99DC68D3166B9B6E4FA21A4026C2AB1C 7M8GdubCAAdh7WUG0DiwRyxTYRKji7HATa7LLJEZ/UAAAAAAVmfUSg== AAAAAFZn1EojfIheIw42bjK3VqkpYyjsQFSbv/dxNna3Q8hUEPKpOw==\n"
  "Commitment sha256 2qZjhYjXODdx122TNUlegLLWWDe5R1B449vx2KU9hsI 41E89EDFBFBA44983E21F18F2230A4ECB5BFB543 17aUsYuMeRjd2N1r8yNyg7aHqRa6gf4z7QPoxxAZbp0AAAAAVmfUSg==\n"
  "Commitment sha256 hujjN0PEfkQlOnBKTH0WlGPOs6PdYoe8tuEMeS6C4cw 36637026573A04110CF3E6B1D201FB9A98B88734 DDDYtripvdOU+XPEUm5xpU64d9IURSds1xSwQsgeB8oAAAAAVmfUSg==\n"
  "SharedRandCurrentValue 3 F1D59E5B5D8A1334C61222C680ED54549ED9F7509E92845CC6DE90F4A8673852\n"
  "SharedRandPreviousValue 4 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

/** Create an SR disk state, parse it and validate that the parsing went
 *  well. Yes! */
static void
test_state_load_from_disk(void *arg)
{
  int ret;
  char *dir = tor_strdup(get_fname("test_sr_state"));
  char *sr_state_path = tor_strdup(get_fname("test_sr_state/sr_state"));
  sr_state_t *the_sr_state = NULL;

  (void) arg;

  /* First try with a nonexistent path. */
  ret = disk_state_load_from_disk_impl("NONEXISTENTNONEXISTENT");
  tt_assert(ret == -ENOENT);

  /* Now create a mock state directory and state file */
#ifdef _WIN32
  ret = mkdir(dir);
#else
  ret = mkdir(dir, 0700);
#endif
  tt_assert(ret == 0);
  ret = write_str_to_file(sr_state_path, sr_state_str, 0);
  tt_assert(ret == 0);

  /* Try to load the directory itself. Should fail. */
  ret = disk_state_load_from_disk_impl(dir);
  tt_assert(ret == -EINVAL);

  /* State should be non-existent at this point. */
  the_sr_state = get_sr_state();
  tt_assert(!the_sr_state);

  /* Now try to load the correct file! */
  ret = disk_state_load_from_disk_impl(sr_state_path);
  tt_assert(ret == 0);

  /* Check the content of the state */
  /* XXX check more deeply!!! */
  the_sr_state = get_sr_state();
  tt_assert(the_sr_state);
  tt_assert(the_sr_state->version == 1);
  tt_assert(digestmap_size(the_sr_state->commitments) == 3);
  tt_assert(the_sr_state->current_srv);
  tt_assert(the_sr_state->current_srv->num_reveals == 3);
  tt_assert(the_sr_state->previous_srv);

  /* XXX Now also try loading corrupted state files and make sure parsing fails */

 done:
  tor_free(dir);
  tor_free(sr_state_path);
}

/** Generate and return three specially crafted commits (based on the test
 *  vector at sr_srv_calc_ref.py).
 *  Helper of test_sr_compute_srv(). Mocks sr_state_get_commits(). */
static digestmap_t *
sr_state_get_commits_mocked(void)
{
  time_t now = time(NULL);
  sr_commit_t *commit_a, *commit_b, *commit_c;
  authority_cert_t *auth_cert = NULL;
  digestmap_t *commits = digestmap_new();


  {  /* Setup a minimal dirauth environment for this test  */
    or_options_t *options = get_options_mutable();

    auth_cert = authority_cert_parse_from_string(AUTHORITY_CERT_1, NULL);
    tt_assert(auth_cert);

    options->AuthoritativeDir = 1;
    tt_int_op(0, ==, load_ed_keys(options, now));
  }

  /* Generate three dummy commitments according to sr_srv_calc_ref.py */

  { /* Commit from auth 'a' */
    commit_a = sr_generate_our_commitment(now, auth_cert);
    tt_assert(commit_a);

    /* Do some surgery on the commit */
    strlcpy(commit_a->auth_fingerprint,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sizeof(commit_a->rsa_identity_fpr));
    strlcpy(commit_a->auth_fingerprint,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sizeof(commit_a->auth_fingerprint));
    strlcpy(commit_a->encoded_reveal,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            sizeof(commit_a->encoded_reveal));
  }

  { /* Commit from auth 'b' */
    commit_b = sr_generate_our_commitment(now, auth_cert);
    tt_assert(commit_b);

    /* Do some surgery on the commit */
    strlcpy(commit_b->auth_fingerprint,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            sizeof(commit_b->rsa_identity_fpr));
    strlcpy(commit_b->auth_fingerprint,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            sizeof(commit_b->auth_fingerprint));
    strlcpy(commit_b->encoded_reveal,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            sizeof(commit_b->encoded_reveal));
  }

  { /* Commit from auth 'c' */
    commit_c = sr_generate_our_commitment(now, auth_cert);
    tt_assert(commit_c);

    /* Do some surgery on the commit */
    strlcpy(commit_c->auth_fingerprint,
            "ccccccccccccccccccccccccccccccccccccccccccccccccc",
            sizeof(commit_c->rsa_identity_fpr));
    strlcpy(commit_c->auth_fingerprint,
            "ccccccccccccccccccccccccccccccccccccccccccc",
            sizeof(commit_c->auth_fingerprint));
    strlcpy(commit_c->encoded_reveal,
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            sizeof(commit_c->encoded_reveal));
  }

  /* Put them in commits and return them! */
  digestmap_set(commits,
                commit_a->rsa_identity_fpr, commit_a);
  digestmap_set(commits,
                commit_b->rsa_identity_fpr, commit_b);
  digestmap_set(commits,
                commit_c->rsa_identity_fpr, commit_c);

  return commits;

 done:
  return NULL;
}

/** Generate a specially crafted previous SRV value (based on the test
 *  vector at sr_srv_calc_ref.py).
 *  Helper of test_sr_compute_srv().  Mocks sr_state_get_previous_srv(). */
static sr_srv_t *
sr_state_get_previous_srv_mocked(void)
{
  sr_srv_t *srv = tor_malloc_zero(sizeof(sr_srv_t));
  srv->num_reveals = 42;
  memcpy(srv->value,
         "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
         sizeof(srv->value));
  return srv;
}

/** Verify that the SRV generation procedure is proper by testing it against
 *  the test vector from ./sr_srv_calc_ref.py. */
static void
test_sr_compute_srv(void *arg)
{
  (void) arg;
  sr_srv_t *current_srv = NULL;

#define SRV_TEST_VECTOR "BD2D7C0D3F9680585828389C787E3D478C3DDFCD1EB39E42A9D7B49D1ABCB7FC"

  /* Mock the necessary functions to inject our test data into
     sr_compute_srv(). */
  MOCK(sr_state_get_commits,
       sr_state_get_commits_mocked);
  MOCK(sr_state_get_previous_srv,
       sr_state_get_previous_srv_mocked);

  {
    sr_state_init(0);
    /* Set ourself in reveal phase */
    set_sr_phase(SR_PHASE_REVEAL);
  }

  /* Compute the SRV */
  sr_compute_srv();

  /* Check the result against the test vector */
  current_srv = sr_state_get_current_srv();
  tt_assert(current_srv);
  tt_str_op(hex_str((char*)current_srv->value, 32),
            ==,
            SRV_TEST_VECTOR);
  tt_int_op(current_srv->num_reveals, ==, 3);

 done:
  UNMOCK(sr_state_get_previous_srv);
  UNMOCK(sr_state_get_commits);
}

/** Return a minimal vote document with a current SRV value set to
 *  <b>srv</b>. */
static networkstatus_t *
get_test_vote_with_curr_srv(const char *srv)
{
  networkstatus_t *vote = tor_malloc_zero(sizeof(networkstatus_t));

  vote->type = NS_TYPE_VOTE;
  vote->sr_info.participate = 1;
  vote->sr_info.current_srv = tor_malloc_zero(sizeof(sr_srv_t));
  vote->sr_info.current_srv->num_reveals = 42;
  memcpy(vote->sr_info.current_srv->value,
         srv,
         sizeof(vote->sr_info.current_srv->value));

  return vote;
}


/* Test the function that picks the right SRV given a bunch of votes. Make sure
 * that the function returns an SRV iff the majority/agreement requirements are
 * met. */
static void
test_sr_get_majority_srv_from_votes(void *arg)
{
  sr_srv_t *chosen_srv;
  smartlist_t *votes = smartlist_new();
  or_options_t *options = get_options_mutable();

#define SRV_1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SRV_2 "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

  (void) arg;

  /* The test relies on the dirauth list being initialized. */
  add_default_trusted_dir_authorities(V3_DIRINFO);
  tt_int_op(get_n_authorities(V3_DIRINFO), >=, 9);

  { /* Prepare voting environment with just a single vote. */
    networkstatus_t *vote = get_test_vote_with_curr_srv(SRV_1);
    smartlist_add(votes, vote);
  }

  /* Since it's only one vote with an SRV, it should not achieve majority and
     hence no SRV will be returned. */
  chosen_srv = get_majority_srv_from_votes(votes, 1);
  tt_assert(!chosen_srv);

  { /* Now put in 8 more votes. Let SRV_1 have majority. */
    int i;
    /* Now 7 votes believe in SRV_1 */
    for (i = 0; i < 6; i++) {
      networkstatus_t *vote = get_test_vote_with_curr_srv(SRV_1);
      smartlist_add(votes, vote);
    }
    /* and 2 votes believe in SRV_2 */
    for (i = 0; i < 2; i++) {
      networkstatus_t *vote = get_test_vote_with_curr_srv(SRV_2);
      smartlist_add(votes, vote);
    }

    tt_int_op(smartlist_len(votes), ==, 9);
  }

  /* Now we achieve majority for SRV_1, but not the AuthDirNumSRVAgreements
     requirement. So still not picking an SRV. */
  chosen_srv = get_majority_srv_from_votes(votes, 1);
  tt_assert(!chosen_srv);

  /* Lower the AuthDirNumSRVAgreements requirement and let's try again.
   * This time it must work. */
  options->AuthDirNumSRVAgreements = 7;
  chosen_srv = get_majority_srv_from_votes(votes, 1);
  tt_assert(chosen_srv);
  tt_int_op(chosen_srv->num_reveals, ==, 42);
  tt_mem_op(chosen_srv->value, OP_EQ, SRV_1, sizeof(chosen_srv->value));

 done:
  SMARTLIST_FOREACH(votes, networkstatus_t *, vote,
                    networkstatus_vote_free(vote));
  smartlist_free(votes);
}

struct testcase_t sr_tests[] = {
  { "get_sr_protocol_phase", test_get_sr_protocol_phase, TT_FORK,
    NULL, NULL },
  { "sr_commit", test_sr_commit, TT_FORK,
    NULL, NULL },
  { "encoding", test_encoding, TT_FORK,
    NULL, NULL },
  { "get_state_valid_until_time", test_get_state_valid_until_time, TT_FORK,
    NULL, NULL },
  { "vote", test_vote, TT_FORK,
    NULL, NULL },
  { "state_load_from_disk", test_state_load_from_disk, TT_FORK,
    NULL, NULL },
  { "sr_compute_srv", test_sr_compute_srv, TT_FORK, NULL, NULL },
  { "sr_get_majority_srv_from_votes", test_sr_get_majority_srv_from_votes,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
