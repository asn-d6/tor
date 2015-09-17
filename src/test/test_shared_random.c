#define SHARED_RANDOM_PRIVATE

#include "or.h"
#include "test.h"
#include "config.h"
#include "shared-random.h"

static void
test_get_sr_protocol_phase(void *arg)
{
  time_t the_time;
  sr_phase_t phase;
  int retval;

  (void) arg;

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 12:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 12:00:01 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 13:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 23:59:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_COMMIT);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 00:00:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 00:00:01 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

  {
    retval = parse_rfc1123_time("Wed, 20 Apr 2015 11:59:00 UTC", &the_time);
    tt_int_op(retval, ==, 0);

    phase = get_sr_protocol_phase(NULL, the_time);
    tt_int_op(phase, ==, SR_PHASE_REVEAL);
  }

 done:
  ;
}

struct testcase_t sr_tests[] = {
  { "get_sr_protocol_phase", test_get_sr_protocol_phase, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};


