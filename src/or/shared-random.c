/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared-random.c
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 **/

#include "shared-random.h"

/* String representation of a protocol phase. */
static const char *phase_str[] = { "unknown", "commit", "reveal" };

/* String representation of a shared random value status. */
static const char *srv_status_str[] = { "fresh", "non-fresh" };

/* Default filename of the shared random state on disk. */
static const char *default_fname = "sr-state";
/* Constant static seed of the shared random value. */
/* static const char *srv_seed = "shared-random"; */
/* Disaster shared random value seed. */
/* static const char *disaster_seed = "shared-random-disaster"; */

/* Shared randomness protocol starts at 12:00 UTC */
#define SHARED_RANDOM_START_HOUR 12
/* Each SR round lasts 1 hour */
#define SHARED_RANDOM_TIME_INTERVAL 1
/* Each protocol phase has 12 rounds  */
#define SHARED_RANDOM_N_ROUNDS 12

/* Return a string representation of a srv status. */
static const char *
get_srv_status_str(sr_srv_status_t status)
{
  switch (status) {
  case SR_SRV_STATUS_FRESH:
  case SR_SRV_STATUS_NONFRESH:
    return srv_status_str[status];
  default:
    /* Unknown status shouldn't be possible. */
    tor_assert(0);
  }
}

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

/* Return a phase value from a name string. */
static sr_phase_t
get_phase_from_str(const char *name)
{
  unsigned int i;
  sr_phase_t phase = -1;

  tor_assert(name);

  for (i = 0; i < ARRAY_LENGTH(phase_str); i++) {
    if (!strcmp(name, phase_str[i])) {
      phase = i;
      break;
    }
  }
  return phase;
}

/* Return a status value from a string. */
static sr_srv_status_t
get_status_from_str(const char *name)
{
  unsigned int i;
  sr_srv_status_t status = -1;

  tor_assert(name);

  for (i = 0; i < ARRAY_LENGTH(srv_status_str); i++) {
    if (!strcmp(name, srv_status_str[i])) {
      status = i;
      break;
    }
  }
  return status;
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

/* Given the consensus 'valid-after' time, return the protocol phase we
 * should be in. */
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

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const uint8_t *identity)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  tor_assert(identity);
  memcpy(commit->identity, identity, sizeof(commit->identity));
  return commit;
}

/* Free a commit object. */
static void
commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  /* Make sure we do not leave OUR random number in memoryr. */
  memwipe(commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/** Helper: deallocate a commit object. (Used with digest256map_free(),
 * which requires a function pointer whose argument is void *). */
static void
commit_free_(void *p)
{
  commit_free(p);
}

/* Allocate a new conflict commit object. If <b>identity</b> is given, it's
 * copied into the object. The commits pointer <b>c1</b> and <b>c2</b> are
 * set in the object as is, they are NOT dup. This means that the caller
 * MUST not free the commits and should consider the conflict object having
 * a reference on them. This never returns NULL. */
static sr_conflict_commit_t *
conflict_commit_new(const uint8_t *identity, sr_commit_t *c1,
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
static void
conflict_commit_free(sr_conflict_commit_t *conflict)
{
  if (conflict == NULL) {
    return;
  }
  commit_free(conflict->commit1);
  commit_free(conflict->commit2);
  tor_free(conflict);
}

/** Helper: deallocate a conflict commit object. (Used with
 * digest256map_free(), which requires a function pointer whose argument is
 * void *). */
static void
conflict_commit_free_(void *p)
{
  conflict_commit_free(p);
}

/* Free a state that was allocated with sr_state_new(). */
static void
state_free(sr_state_t *state)
{
  if (state == NULL) {
    return;
  }
  tor_free(state->fname);
  digest256map_free(state->commitments, commit_free_);
  digest256map_free(state->conflicts, conflict_commit_free_);
  tor_free(state);
}

/* Allocate an sr_state_t object and returns it. If no <b>fname</b>, the
 * default file name is used. This function does NOT initialize the state
 * timestamp, phase or shared random value. NULL is never returned. */
static sr_state_t *
state_new(const char *fname)
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
