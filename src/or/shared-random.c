/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared-random.c
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 **/

#define SHARED_RANDOM_PRIVATE

#include "shared-random.h"
#include "config.h"
#include "routerkeys.h"

/* String representation of a protocol phase. */
static const char *phase_str[] = { "unknown", "commit", "reveal" };
/* Default filename of the shared random state on disk. */
static const char *default_fname = "sr-state";

static sr_state_t *our_sr_state = NULL;

/* Shared randomness protocol starts at 12:00 UTC */
#define SHARED_RANDOM_START_HOUR 12
/* Each SR round lasts 1 hour */
#define SHARED_RANDOM_TIME_INTERVAL 1
/* Each protocol phase has 12 rounds  */
#define SHARED_RANDOM_N_ROUNDS 12

/* Return a string representation of a protocol phase. */
static const char *
get_phase_str(sr_phase_t phase)
{
  switch (phase) {
  case SR_PHASE_UNKNOWN:
  case SR_PHASE_COMMIT:
  case SR_PHASE_REVEAL:
    return phase_str[phase];
  default:
    /* Unknown phase shouldn't be possible. */
    tor_assert(0);
  }
}

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
sr_commit_t *
sr_commit_new(const uint8_t *identity)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  tor_assert(identity);
  memcpy(commit->identity, identity, sizeof(commit->identity));
  return commit;
}

/* Free a commit object. */
void
sr_commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  tor_free(commit->reveal_hash);
  tor_free(commit->signature);
  /* Make sure we do not leave OUR random number in memoryr. */
  memwipe(&commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/** Helper: deallocate a commit object. (Used with digest256map_free(),
 * which requires a function pointer whose argument is void *). */
static void
commit_free_(void *p)
{
  sr_commit_free(p);
}

/* Allocate a new conflict commit object. If <b>identity</b> is given, it's
 * copied into the object. The commits pointer <b>c1</b> and <b>c2</b> are
 * set in the object as is, they are NOT dup. This means that the caller
 * MUST not free the commits and should consider the conflict object having
 * a reference on them. This never returns NULL. */
sr_conflict_commit_t *
sr_conflict_commit_new(const uint8_t *identity, sr_commit_t *c1,
                       sr_commit_t *c2)
{
  sr_conflict_commit_t *conflict = tor_malloc_zero(sizeof(*conflict));
  if (identity != NULL) {
    memcpy(conflict->identity, identity, sizeof(conflict->identity));
  }
  tor_assert(c1);
  tor_assert(c2);
  conflict->commit1 = c1;
  conflict->commit2 = c2;
  return conflict;
}

/* Free a conflict commit object. */
void
sr_conflict_commit_free(sr_conflict_commit_t *conflict)
{
  if (conflict == NULL) {
    return;
  }
  sr_commit_free(conflict->commit1);
  sr_commit_free(conflict->commit2);
  tor_free(conflict);
}

/** Helper: deallocate a conflict commit object. (Used with
 * digest256map_free(), which requires a function pointer whose argument is
 * void *). */
static void
conflict_commit_free_(void *p)
{
  sr_conflict_commit_free(p);
}

/* Allocate an sr_state_t object and returns it. If no <b>fname</b>, the
 * default file name is used. This function does NOT initialize the state
 * timestamp, phase or shared random value. NULL is never returned. */
static sr_state_t *
sr_state_new(const char *fname)
{
  sr_state_t *new_state = tor_malloc_zero(sizeof(*new_state));
  /* If file name is not provided, use default. */
  if (fname == NULL) {
    fname = default_fname;
  }
  new_state->fname = tor_strdup(fname);
  new_state->version = SR_PROTO_VERSION;
  new_state->commitments = digest256map_new();
  new_state->conflicts = digest256map_new();

  return new_state;
}

/* Free a state that was allocated with sr_state_new(). */
void
sr_state_free(sr_state_t *state)
{
  if (state == NULL) {
    return;
  }
  tor_free(state->fname);
  digest256map_free(state->commitments, commit_free_);
  digest256map_free(state->conflicts, conflict_commit_free_);
  tor_free(state);
}

/** Return the current protocol phase on a testing network. */
static time_t
get_testing_network_protocol_phase(sr_state_t *sr_state)
{
  /* XXX In this function we assume that in a testing network all dirauths
     started together. Otherwise their phases will get desynched!!! */

  /* If we just booted, always start with commitment phase. */
  if (sr_state->phase == SR_PHASE_UNKNOWN) {
    return SR_PHASE_COMMIT;
  }

  /* On testing network, instead of messing with time, we simply count the
   * number of rounds and switch phase when we reach the right amount of
   * rounds */
  if (sr_state->phase == SR_PHASE_COMMIT) {
    /* Check if we've done all commitment rounds and we are moving to reveal */
    if (sr_state->n_commit_rounds == SHARED_RANDOM_N_ROUNDS) {
      return SR_PHASE_REVEAL; /* we switched to reveal phase */
    } else {
      return SR_PHASE_COMMIT; /* still more rounds to go on commit phase */
    }
  } else { /* phase is reveal */
    /* Check if we've done all reveal rounds and we are moving to commitment */
    if (sr_state->n_reveal_rounds == SHARED_RANDOM_N_ROUNDS) {
      return SR_PHASE_COMMIT; /* we switched to commit phase */
    } else {
      return SR_PHASE_REVEAL; /* still more rounds to go on reveal phase */
    }
  }

  tor_assert(0); /* should never get here */
}

/* Given the consensus 'valid-after' time, return the protocol phase we should
 * be in. */
STATIC sr_phase_t
get_sr_protocol_phase(sr_state_t *sr_state, time_t valid_after)
{
  sr_phase_t phase;
  struct tm tm;

  /* Testing network requires special handling (since voting happens every few
     seconds). */
  if (get_options()->TestingTorNetwork) {
    return get_testing_network_protocol_phase(sr_state);
  }

  /* Break down valid_after to secs/mins/hours */
  tor_gmtime_r(&valid_after, &tm); /* XXX check retval */

  { /* Now get the phase */
    int hour_commit_phase_begins = SHARED_RANDOM_START_HOUR;

    int hour_commit_phase_ends = hour_commit_phase_begins +
      SHARED_RANDOM_TIME_INTERVAL * SHARED_RANDOM_N_ROUNDS;

    if (tm.tm_hour >= hour_commit_phase_begins &&
        tm.tm_hour < hour_commit_phase_ends) {
      phase = SR_PHASE_COMMIT;
    } else {
      phase = SR_PHASE_REVEAL;
    }
  }

  return phase;
}

#define RANDOM_VALUE_LEN 32

  /* We need 4 bytes for timestamp and the rest for the random value */
#define REVEAL_LEN 4 + RANDOM_VALUE_LEN

/** Generate the commitment/reveal value for the protocol run starting at
 *  <b>timestamp</b>. */
static sr_commit_t *
generate_sr_commitment(time_t timestamp)
{
  /* Data for the reveal */
  uint8_t random_value[RANDOM_VALUE_LEN];
  uint8_t reveal[REVEAL_LEN];
  char reveal_base64[5*REVEAL_LEN]; /* XXX is this enough space? */

  /* Data for the commit */
  char hashed_reveal[DIGEST256_LEN];
  char commit_base64[400]; /* XXX XXX? */

  /* We first need to create the reveal value */

  /* Generate the random value */
  if (crypto_rand((char*)random_value, RANDOM_VALUE_LEN) < 0) {
    log_warn(LD_REND, "Unable to generate reveal random value!");
    return NULL;
  }

  /* Now prepare the binary representation of reveal */
  set_uint32(reveal, htonl((uint32_t)timestamp));
  memcpy(reveal+4, random_value, RANDOM_VALUE_LEN);

  /* And now base64 encode the reveal value */
  if (base64_encode(reveal_base64, sizeof(reveal_base64),
                    (const char *)reveal, REVEAL_LEN,
                    0)<0) {
    log_warn(LD_GENERAL, "Could not encode reveal to base64");
    return NULL;
  }

  log_warn(LD_GENERAL, "[SR] Created reveal value: %s", reveal_base64);

  /* And now we can create the reveal value */
  crypto_digest256(hashed_reveal,
                   (const char*)reveal_base64, strlen(reveal_base64),
                   DIGEST_SHA256);

  /* And now base64 encode the reveal value */
  if (base64_encode(commit_base64, sizeof(commit_base64),
                    (const char *)hashed_reveal, DIGEST256_LEN,
                    0)<0) {
    log_warn(LD_GENERAL, "Could not encode commit to base64");
    return NULL;
  }

  /* XXX make actual commitment. Not H(REVEAL). */

  return NULL;
}

/** This is the first round of the new protocol run starting at <b>valid_after</b>.
 *
 *   In the beginning of each protocol run we need to do some things:
 *       - Reset all the counters and stuff of the old protocol run.
 *       - Compute the shared randomness value of the day.
 *       - Wipe all the now useless commitment/reveal values.
 *       - Generate new commitments
 */
static int
update_state_new_protocol_run(sr_state_t *sr_state, time_t valid_after)
{
  /* Reset timers */
  sr_state->n_reveal_rounds = 0;
  sr_state->n_commit_rounds = 0;

  /* Compute the shared randomness value of the day. */
  ;

  /* Wipe old commit/reveal values */
  ;

  /* Generate new commitments */
  generate_sr_commitment(valid_after);

  return 1;
}

/** Update the current SR state as needed for the upcoming voting round at
 *  <b>valid_after</b>.  Don't call this function twice in the same voting
 *  period!!! */
static void
update_state(sr_state_t *sr_state, time_t valid_after)
{
  int is_new_protocol_run = 0;
  /* Get the new protocol phase according to the current hour */
  sr_phase_t new_phase = get_sr_protocol_phase(sr_state, valid_after);
  tor_assert(new_phase != SR_PHASE_UNKNOWN);

  /* See if we just entered a new protocol run. */
  if (sr_state->phase == SR_PHASE_UNKNOWN ||
      (sr_state->phase == SR_PHASE_REVEAL && new_phase == SR_PHASE_COMMIT)) {
    is_new_protocol_run = 1;
  }

  /* Get the phase of this round */
  sr_state->phase = new_phase;

  /* Check if we are now starting a new protocol run and if yes, do the necessary
     operations */
  if (is_new_protocol_run) {
    update_state_new_protocol_run(sr_state, valid_after);
  }

  /* Count the current round */
  if (sr_state->phase == SR_PHASE_COMMIT) {
    /* invariant check: we've not entered reveal phase yet */
    tor_assert(sr_state->n_reveal_rounds == 0);

    sr_state->n_commit_rounds++;
  } else {
    /* invariant check: we've completed commit phase */
    tor_assert(sr_state->n_commit_rounds == SHARED_RANDOM_N_ROUNDS);

    sr_state->n_reveal_rounds++;
  }

  { /* Some debugging */
    char tbuf[ISO_TIME_LEN+1];
    struct tm tm;
    tor_gmtime_r(&valid_after, &tm); /* XXX check retval */
    format_iso_time(tbuf, valid_after);
    log_notice(LD_DIR, "[SR] Preparing vote with valid-after %s. Phase is %s (%d/%d).",
               tbuf, get_phase_str(sr_state->phase),
               sr_state->n_commit_rounds, sr_state->n_reveal_rounds);
  }

  return;
}

/* Get the current shared random state we are going to be using for the
 * consensus at <b>valid_after</b>. This function should be called at each new
 * voting period. */
const sr_state_t *
sr_get_current_state(time_t valid_after)
{
  if (!our_sr_state) {
    /* TODO Replace NULL fname with a config parameter */
    our_sr_state = sr_state_new(NULL);
  }

  /* Update the old state with information about this new round */
  update_state(our_sr_state, valid_after);
}
