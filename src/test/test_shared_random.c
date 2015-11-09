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


/* In this test we are going to generate our own commit/reveal values
   and valida them.

   We first generate our values, and then we parse them as if they
   were received from the network. After we parse both the commit and
   the reveal, we verify that they inded match. */
static void
test_generate_commitment(void *arg)
{
  int retval;
  authority_cert_t *auth_cert = NULL;
  char commit_b64[SR_COMMIT_BASE64_LEN + 1];
  char reveal_b64[SR_REVEAL_BASE64_LEN + 1];
  time_t now = time(NULL);

  (void) arg;

  /* This is the commit we generated */
  sr_commit_t *our_commit = NULL;
  /* This is our own commit that we parsed */
  sr_commit_t *parsed_commit = tor_malloc_zero(sizeof(sr_commit_t));

  (void) arg;

  {  /* Setup a minimal dirauth environment for this test  */
    or_options_t *options = get_options_mutable();

    auth_cert = authority_cert_parse_from_string(AUTHORITY_CERT_1, NULL);
    tt_assert(auth_cert);

    options->AuthoritativeDir = 1;
    tt_int_op(0, ==, load_ed_keys(options, now));

    sr_state_init(0);
    set_sr_phase_to_reveal();
  }

  { /* Generate our commit/reveal */
    our_commit = sr_generate_our_commitment(now, auth_cert);
    tt_assert(our_commit);
  }

  { /* Get the encodings of our commit/reveal. */
    commit_encode(our_commit, commit_b64, sizeof(commit_b64));
    reveal_encode(our_commit, reveal_b64, sizeof(reveal_b64));
  }

  { /* Parse our own commit */

    /* First copy auth information */
    memcpy(&parsed_commit->auth_fingerprint, &our_commit->auth_fingerprint,
           sizeof(parsed_commit->auth_fingerprint));
    memcpy(&parsed_commit->auth_identity, &our_commit->auth_identity,
           sizeof(parsed_commit->auth_identity));

    retval = commit_decode(commit_b64, parsed_commit);
    tt_int_op(retval, ==, 0);
  }

  { /* Parse our own reveal */
    retval = reveal_decode(reveal_b64, parsed_commit);
    tt_int_op(retval, ==, 0);
  }

  { /* Verify the commit with the reveal */
    retval = verify_received_commit(parsed_commit);
    tt_int_op(retval, ==, 0);
  }

 done:
  tor_free(parsed_commit);
}

struct testcase_t sr_tests[] = {
  { "get_sr_protocol_phase", test_get_sr_protocol_phase, TT_FORK,
    NULL, NULL },
  { "generate_commitment", test_generate_commitment, TT_FORK,
    NULL, NULL },
  { "get_state_valid_until_time", test_get_state_valid_until_time, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};


