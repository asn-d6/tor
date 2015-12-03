#define SHARED_RANDOM_PRIVATE
#define SHARED_RANDOM_STATE_PRIVATE

#include "or.h"
#include "test.h"
#include "config.h"
#include "shared-random.h"
#include "shared-random-state.h"
#include "routerkeys.h"
#include "router.h"
#include "routerparse.h"

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

struct testcase_t sr_tests[] = {
  { "get_sr_protocol_phase", test_get_sr_protocol_phase, TT_FORK,
    NULL, NULL },
  { "sr_commit", test_sr_commit, TT_FORK,
    NULL, NULL },
  { "encoding", test_encoding, TT_FORK,
    NULL, NULL },
  { "get_state_valid_until_time", test_get_state_valid_until_time, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};
