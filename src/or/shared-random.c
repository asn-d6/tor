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
#include "confparse.h"
#include "routerkeys.h"
#include "router.h"
#include "routerlist.h"

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

/* Our shared random protocol state. There is only one possible state per
 * protocol run so this is the global state which is reset at every run once
 * the shared random value has been computed. */
static sr_state_t *sr_state = NULL;

/* Representation of our persistent state on disk. The sr_state above
 * contains the data parsed from this state. When we save to disk, we
 * translate the sr_state to this sr_disk_state. */
static sr_disk_state_t *sr_disk_state = NULL;

/* Disk state file keys. */
static const char *dstate_commit_key = "Commitment";
static const char *dstate_conflict_key = "Conflict";
static const char *dstate_prev_srv_key = "SharedRandPreviousValue";
static const char *dstate_cur_srv_key = "SharedRandCurrentValue";

/* XXX: These next two are duplicates or near-duplicates from config.c */
#define VAR(name, conftype, member, initvalue)                              \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(sr_disk_state_t, member), \
    initvalue }
/** As VAR, but the option name and member name are the same. */
#define V(member, conftype, initvalue) \
  VAR(#member, conftype, member, initvalue)
/* Our persistent state magic number. Yes we got the 42s! */
#define SR_DISK_STATE_MAGIC 42424242

/* Shared randomness protocol starts at 12:00 UTC */
#define SHARED_RANDOM_START_HOUR 12
/* Each SR round lasts 1 hour */
#define SHARED_RANDOM_TIME_INTERVAL 1
/* Each protocol phase has 12 rounds  */
#define SHARED_RANDOM_N_ROUNDS 12

static int
disk_state_validate_cb(void *old_state, void *state, void *default_state,
                       int from_setconf, char **msg);

/* Array of variables that are saved to disk as a persistent state. */
static config_var_t state_vars[] = {
  V(Version,                    INT, "1"),
  V(ValidUntil,                 ISOTIME, NULL),
  V(ProtocolPhase,              STRING, NULL),

  V(Commitments,                LINELIST_S, NULL),
  V(Conflicts,                  LINELIST_S, NULL),

  V(SharedRandPreviousValue,    LINELIST_S, NULL),
  V(SharedRandCurrentValue,     LINELIST_S, NULL),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};

/* "Extra" variable in the state that receives lines we can't parse. This
 * lets us preserve options from versions of Tor newer than us. */
static config_var_t state_extra_var = {
  "__extra", CONFIG_TYPE_LINELIST,
  STRUCT_OFFSET(sr_disk_state_t, ExtraLines), NULL
};

/* Configuration format of sr_disk_state_t. */
static const config_format_t state_format = {
  sizeof(sr_disk_state_t),
  SR_DISK_STATE_MAGIC,
  STRUCT_OFFSET(sr_disk_state_t, magic_),
  NULL,
  state_vars,
  disk_state_validate_cb,
  &state_extra_var,
};

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
get_testing_network_protocol_phase(void)
{
  /* XXX In this function we assume that in a testing network all dirauths
     started together. Otherwise their phases will get desynched!!! */

  /* XXX: This can be called when allocating a new state so in this case we
   * are starting up thus in commit phase. */
  if (sr_state == NULL) {
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
get_sr_protocol_phase(time_t valid_after)
{
  sr_phase_t phase;
  struct tm tm;

  /* Testing network requires special handling (since voting happens every few
     seconds). */
  if (get_options()->TestingTorNetwork) {
    return get_testing_network_protocol_phase();
  }

  /* Break down valid_after to secs/mins/hours */
  tor_gmtime_r(&valid_after, &tm);

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

/* Using the time right now as this function is called, return the shared
 * random state valid until time that is to the next protocol run. */
static time_t
get_valid_until_time(void)
{
  char tbuf[ISO_TIME_LEN + 1];
  time_t valid_until, now = time(NULL);
  struct tm tm;

  tor_gmtime_r(&now, &tm);
  {
    /* Compute the hour difference and if positive, the value is the amount
     * of hours missing before hitting the mark. Else, it's the next day at
     * the start hour. */
    int diff_hour = SHARED_RANDOM_START_HOUR - tm.tm_hour;
    if (diff_hour <= 0) {
      /* We are passed that hour. Add one because hour starts at 0. */
      tm.tm_hour = SHARED_RANDOM_START_HOUR + 1;
      tm.tm_mday += 1;
    } else {
      /* Add one here because hour starts at 0 for struct tm. */
      tm.tm_hour += diff_hour + 1;
    }
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = 0;
  }
  valid_until = mktime(&tm);
  /* This should really not happen else serious issue. */
  tor_assert(valid_until != -1);
  format_iso_time(tbuf, valid_until);
  log_debug(LD_DIR, "[SR] Valid until time for state set to %s.", tbuf);

  return valid_until;
}

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const ed25519_public_key_t *identity)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  tor_assert(identity);
  memcpy(&commit->auth_identity, identity, sizeof(commit->auth_identity));
  /* This call can't fail. */
  ed25519_public_to_base64(commit->auth_fingerprint, identity);
  return commit;
}

/* Free a commit object. */
static void
commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  /* Make sure we do not leave OUR random number in memory. */
  memwipe(commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/* Helper: deallocate a commit object. (Used with digest256map_free(),
 * which requires a function pointer whose argument is void *). */
static void
commit_free_(void *p)
{
  commit_free(p);
}

/* Dup the given <b>orig</b> commit and return the newly allocated commit
 * object that is the exact same copy as orig. */
static sr_commit_t *
commit_dup(const sr_commit_t *orig)
{
  sr_commit_t *new;
  tor_assert(orig);
  new = commit_new(&orig->auth_identity);
  memcpy(new, orig, sizeof(*new));
  return new;
}

/* Issue a log message describing <b>commit</b>. */
static void
commit_log(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_warn(LD_GENERAL, "Commit by %s", commit->auth_fingerprint);

  if (commit->commit_ts >= 0) {
    log_warn(LD_GENERAL, "C: [TS: %u] [SIG: %s...]",
           (unsigned) commit->commit_ts,
           hex_str((char *)commit->commit_signature.sig, 5));
  }

  if (commit->reveal_ts >= 0 && commit->random_number) {
    log_warn(LD_GENERAL, "R: [TS: %u] [RN: %s...]",
           (unsigned) commit->reveal_ts,
           hex_str((char *)commit->random_number, 5));
  } else {
    log_warn(LD_GENERAL, "R: UNKNOWN");
  }
}

/* Allocate a new conflict commit object. If <b>identity</b> is given, it's
 * copied into the object. The commits pointer <b>c1</b> and <b>c2</b> are
 * set in the object as is, they are NOT dup. This means that the caller
 * MUST not free the commits and should consider the conflict object having
 * a reference on them. This never returns NULL. */
static sr_conflict_commit_t *
conflict_commit_new(sr_commit_t *c1, sr_commit_t *c2)
{
  sr_conflict_commit_t *conflict = tor_malloc_zero(sizeof(*conflict));

  tor_assert(c1);
  tor_assert(c2);

  /* This is should NEVER happen else code flow issue. */
  int key_are_equal = tor_memeq(&c1->auth_identity, &c2->auth_identity,
                                sizeof(c1->auth_identity));
  tor_assert(key_are_equal);

  memcpy(&conflict->auth_identity, &c1->auth_identity,
         sizeof(conflict->auth_identity));
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

/* Helper: deallocate a conflict commit object. (Used with
 * digest256map_free(), which requires a function pointer whose argument is
 * void *). */
static void
conflict_commit_free_(void *p)
{
  conflict_commit_free(p);
}

/* Add a conflict commit to the global state. */
static void
conflict_commit_add(sr_conflict_commit_t *conflict)
{
  sr_conflict_commit_t *old;

  tor_assert(conflict);

  /* Replace current value if any and free the old one if any. */
  old = digest256map_set(sr_state->conflicts,
                         conflict->auth_identity.pubkey, conflict);
  conflict_commit_free(old);
  {
    /* Logging. */
    char ed_b64[BASE64_DIGEST256_LEN + 1];
    ed25519_public_to_base64(ed_b64, &conflict->auth_identity);
    log_warn(LD_GENERAL, "Authority %s has just triggered a shared random "
                         "commit conflict. It will be ignored for the rest "
                         "of the protocol run.", ed_b64);
  }
}

/* Add the given commit to state. It MUST be valid. If a commit already
 * exists, a conflict is created and the state is updated. */
static void
commit_add(sr_commit_t *commit)
{
  sr_commit_t *old_commit;

  tor_assert(commit);
  tor_assert(sr_state);

  /* Remove the current commit of this authority from state so if one exist,
   * our conflict object can get the ownership. If none exist, no conflict
   * so we can add the commit to the state. */
  old_commit = digest256map_remove(sr_state->commitments,
                                   commit->auth_identity.pubkey);
  if (old_commit != NULL) {
    /* Create conflict for this authority identity and update the state. */
    sr_conflict_commit_t *conflict =
      conflict_commit_new(old_commit, commit);
    conflict_commit_add(conflict);
  } else {
    /* Set it in state. */
    digest256map_set(sr_state->commitments, commit->auth_identity.pubkey,
                     commit);
    log_info(LD_GENERAL, "Commit from authority %s has been saved.",
             commit->auth_fingerprint);
  }
}

/* Free a state that was allocated with state_new(). */
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
  new_state->phase = get_sr_protocol_phase(time(NULL));
  new_state->valid_until = get_valid_until_time();
  return new_state;
}

/* Set our global state pointer with the one given. */
static void
state_set(sr_state_t *state)
{
  tor_assert(state);
  if (sr_state != NULL) {
    state_free(sr_state);
  }
  sr_state = state;
}

/* Free an allocated disk state. */
static void
disk_state_free(sr_disk_state_t *state)
{
  config_free(&state_format, state);
  tor_free(state);
}

/* Make sure that the commitment and reveal information in <b>commit</b>
 * match. If they match return 0, return -1 otherwise. This function MUST be
 * used everytime we receive a new reveal value. */
STATIC int
verify_commit_and_reveal(const sr_commit_t *commit)
{
  tor_assert(commit);

  /* Check that the timestamps match. */
  if (commit->commit_ts != commit->reveal_ts) {
    log_warn(LD_DIR, "[SR] Commit timestamp %ld doesn't match reveal "
                     "timestamp %ld", commit->commit_ts, commit->reveal_ts);
    goto invalid;
  }

  /* Verify that the hashed_reveal received in the COMMIT message, matches
   * the reveal we just received. */
  {
    /* We first hash the reveal we just received. */
    char received_hashed_reveal[sizeof(commit->hashed_reveal)];
    if (crypto_digest256(received_hashed_reveal,
                         commit->encoded_reveal,
                         sizeof(commit->encoded_reveal),
                         DIGEST_SHA256) < 0) {
      /* Unable to digest the reveal blob, this is unlikely. */
      goto invalid;
    }
    /* Now compare that with the hashed_reveal we received in COMMIT. */
    if (tor_memneq(received_hashed_reveal, commit->hashed_reveal,
                   sizeof(received_hashed_reveal))) {
      log_warn(LD_DIR, "[SR] Commitment didn't match reveal:");
      commit_log(commit);
      goto invalid;
    }
  }

  return 0;
 invalid:
  return -1;
}

/* We just received <b>commit</b> in a vote. Make sure that it's conforming
 * to the current protocol phase. Verify its signature and timestamp. */
static int
verify_received_commit(const sr_commit_t *commit)
{
  int have_reveal;

  tor_assert(commit);

  /* Let's verify the signature of the commitment. */
  if (ed25519_checksig(&commit->commit_signature,
                       (const uint8_t *) commit->encoded_commit,
                       SR_COMMIT_SIG_BODY_LEN, &commit->auth_identity) < 0) {
    log_warn(LD_GENERAL, "[SR] Commit signature from %s is invalid!",
             commit->auth_fingerprint);
    goto invalid;
  }

  have_reveal = !tor_mem_is_zero(commit->encoded_reveal,
                                 sizeof(commit->encoded_reveal));

  switch (sr_state->phase) {
  case SR_PHASE_COMMIT:
    /* During commit phase, we shouldn't get a reveal value and if so this
     * is considered as a malformed commit thus invalid. */
    if (have_reveal) {
      log_warn(LD_DIR, "Found commit with reveal value during commit phase.");
      goto invalid;
    }
    break;
  case SR_PHASE_REVEAL:
    /* We do have a reveal so let's verify it. */
    if (have_reveal && verify_commit_and_reveal(commit) < 0) {
      goto invalid;
    }
    break;
  default:
    goto invalid;
  }

  return 0;
 invalid:
  return -1;
}

/* Allocate a new disk state, initialized it and return it. */
static sr_disk_state_t *
disk_state_new(void)
{
  config_line_t *line;
  sr_disk_state_t *new_state = tor_malloc_zero(sizeof(*new_state));

  new_state->magic_ = SR_DISK_STATE_MAGIC;
  new_state->Version = SR_PROTO_VERSION;
  new_state->ValidUntil = get_valid_until_time();

  /* Shared random values. */
  line = new_state->SharedRandPreviousValue =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_prev_srv_key);
  line = new_state->SharedRandCurrentValue=
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_cur_srv_key);

  /* Init Commitments and Conflicts line. */
  line = new_state->Commitments =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_commit_key);
  line = new_state->Conflicts =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_conflict_key);

  /* Init config format. */
  config_init(&state_format, new_state);
  return new_state;
}

/* Set our global disk state with the given state. */
static void
disk_state_set(sr_disk_state_t *state)
{
  tor_assert(state);
  if (sr_disk_state != NULL) {
    disk_state_free(sr_disk_state);
  }
  sr_disk_state = state;
}

static int
disk_state_validate(sr_disk_state_t *state)
{
  (void) state;
  /* TODO: */
  return 0;
}

static int
disk_state_validate_cb(void *old_state, void *state, void *default_state,
                       int from_setconf, char **msg)
{
  /* We don't use these; only options do. Still, we need to match that
   * signature. */
  (void) from_setconf;
  (void) default_state;
  (void) old_state;

  /* TODO: Validate state file entries. */
  (void) state;
  (void) msg;
  return 0;
}

/* Parse the encoded commit. The format is:
 *    base64-encode(H(REVEAL) || TIMESTAMP || SIGNATURE)
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
STATIC int
parse_encoded_commit(const char *encoded, sr_commit_t *commit)
{
  size_t offset;
  char b64_decoded[SR_COMMIT_LEN + 1];

  tor_assert(encoded);
  tor_assert(commit);

  /* Decode our encoded commit. */
  if (base64_decode(b64_decoded, sizeof(b64_decoded),
                    encoded, strlen(encoded)) < 0) {
    log_warn(LD_GENERAL, "Commit can't be bas64-decoded.");
    goto error;
  }

  commit->commit_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  /* Next is the hash of the reveal value. */
  offset = sizeof(uint64_t);
  memcpy(commit->hashed_reveal, b64_decoded + offset,
         sizeof(commit->hashed_reveal));
  /* Next is the signature of the commit. */
  offset += sizeof(commit->hashed_reveal);
  memcpy(&commit->commit_signature.sig, b64_decoded + offset,
         sizeof(commit->commit_signature.sig));
  /* Copy the base64 blob to the commit. Useful for voting. */
  memcpy(commit->encoded_commit, encoded, sizeof(commit->encoded_commit));

  log_warn(LD_GENERAL, "Parsed commit:");
  commit_log(commit);

  return 0;
error:
  return -1;
}

/* Parse the b64 blob at <b>encoded</b> containin reveal information
   and store the information in-place in <b>commit</b>. */
STATIC int
parse_encoded_reveal(const char *encoded, sr_commit_t *commit)
{
  char b64_buffer[SR_REVEAL_BASE64_LEN + 1];
  if (base64_decode(b64_buffer, sizeof(b64_buffer),
                    encoded, strlen(encoded)) < 0) {
    log_warn(LD_GENERAL, "Commitment line b64 reveal is not recognized.");
    return -1;
  }

  commit->reveal_ts = (time_t) tor_ntohll(get_uint64(b64_buffer));

  /* Copy the last part, the random value. */
  memcpy(commit->random_number, b64_buffer + sizeof(uint64_t),
         sizeof(commit->random_number));
  /* Also copy the whole message to use during verification */
  memcpy(commit->encoded_reveal, encoded, sizeof(commit->encoded_reveal));

  log_warn(LD_GENERAL, "Parsed reveal:");
  commit_log(commit);

  return 0;
}

/* Parse a Commitment line from our disk state and return a newly allocated
 * commit object. NULL is returned on error. */
static sr_commit_t *
parse_commitment_line(smartlist_t *args)
{
  char *value;
  ed25519_public_key_t pubkey;
  digest_algorithm_t alg;
  sr_commit_t *commit = NULL;

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_GENERAL, "Commitment line algorithm is not recognized.");
    goto error;
  }
  /* Second arg is the authority identity. */
  value = smartlist_get(args, 1);
  if (ed25519_public_from_base64(&pubkey, value) < 0) {
    log_warn(LD_GENERAL, "Commitment line identity is not recognized.");
    goto error;
  }
  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(&pubkey);

  /* Third argument is the majority value. 0 or 1. */
  value = smartlist_get(args, 2);
  commit->has_majority = !!strcmp(value, "0");

  /* Fourth and fifth arguments is the ISOTIME.
  tor_snprintf(isotime, sizeof(isotime), "%s %s",
               (char *) smartlist_get(args, 3),
               (char *) smartlist_get(args, 4));
  if (parse_iso_time(isotime, &commit->received_ts) < 0) {
    log_warn(LD_GENERAL, "Commitment line timestamp is not recognized.");
    goto error;
  }
  */
  /* Fourth argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 3);
  if (parse_encoded_commit(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fifth argument is the revealed value. */
  value = smartlist_get(args, 4);
  if (value != NULL) {
    if (parse_encoded_reveal(value, commit) < 0) {
      goto error;
    }
  }

  return commit;
error:
  commit_free(commit);
  return NULL;
}

/* Parse the Commitment line(s) in the disk state and translate them to the
 * the memory state. Return 0 on success else -1 on error. */
static int
disk_state_parse_commits(sr_state_t *state, sr_disk_state_t *disk_state)
{
  config_line_t *line;

  tor_assert(state);
  tor_assert(disk_state);

  for (line = disk_state->Commitments; line; line = line->next) {
    smartlist_t *args;
    sr_commit_t *commit = NULL;

    if (strcasecmp(line->key, dstate_commit_key) ||
        line->value == NULL) {
      /* Ignore any lines that are not commits. */
      continue;
    }
    args = smartlist_new();
    smartlist_split_string(args, line->value, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args) < 6) {
      log_warn(LD_GENERAL, "Too few arguments to Commitment. Line: \"%s\"",
               line->value);
      goto error;
    }
    commit = parse_commitment_line(args);
    if (commit == NULL) {
      goto error;
    }
    /* Update state. */
    commit_add(commit);

    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
  }

  return 0;
error:
  return -1;
}

/* Parse a Conflict line from our disk state and return a newly allocated
 * conflict commit object. NULL is returned on error. */
static sr_conflict_commit_t *
parse_conflict_line(smartlist_t *args)
{
  char *value;
  ed25519_public_key_t identity;
  sr_commit_t *commit1 = NULL, *commit2 = NULL;
  sr_conflict_commit_t *conflict = NULL;

  /* First argument is the authority identity. */
  value = smartlist_get(args, 0);
  if (ed25519_public_from_base64(&identity, value) < 0) {
    log_warn(LD_GENERAL, "Conflict line identity is not recognized.");
    goto error;
  }
  /* Second argument is the first commit value base64-encoded. */
  commit1 = commit_new(&identity);
  value = smartlist_get(args, 5);
  if (parse_encoded_commit(value, commit1) < 0) {
    goto error;
  }
  /* Third argument is the second commit value base64-encoded. */
  commit2 = commit_new(&identity);
  value = smartlist_get(args, 5);
  if (parse_encoded_commit(value, commit2) < 0) {
    goto error;
  }
  /* Everything is parsing correctly, allocate object and return it. */
  conflict = conflict_commit_new(commit1, commit2);
  return conflict;
error:
  conflict_commit_free(conflict);
  commit_free(commit1);
  commit_free(commit2);
  return NULL;
}

/* Parse Conflict line(s) in the disk state and translate them to the the
 * memory state. Return 0 on success else -1 on error. */
static int
disk_state_parse_conflicts(sr_state_t *state, sr_disk_state_t *disk_state)
{
  config_line_t *line;

  tor_assert(state);
  tor_assert(disk_state);

  for (line = disk_state->Conflicts; line; line = line->next) {
    smartlist_t *args;
    sr_conflict_commit_t *conflict = NULL;

    if (strcasecmp(line->key, dstate_conflict_key) ||
        line->value == NULL) {
      /* Ignore any lines that are not conflicts. */
      continue;
    }
    args = smartlist_new();
    smartlist_split_string(args, line->value, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args) < 3) {
      log_warn(LD_GENERAL, "Too few arguments to Conflict. Line: \"%s\"",
               line->value);
      goto error;
    }
    conflict = parse_conflict_line(args);
    if (conflict == NULL) {
      goto error;
    }
    /* Update state. */
    conflict_commit_add(conflict);

    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
  }

  return 0;
error:
  return -1;
}

/* Parse a share random value line from the disk state and save it to dst
 * which is an allocated srv object. Return 0 on success else -1. */
static int
disk_state_parse_srv(const char *value, sr_srv_t *dst)
{
  char *srv;
  smartlist_t *args;
  sr_srv_status_t status;

  tor_assert(value);
  tor_assert(dst);

  args = smartlist_new();
  smartlist_split_string(args, value, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(args) < 2) {
    log_warn(LD_GENERAL, "Too few arguments to shared random value. "
             "Line: \"%s\"", value);
    goto error;
  }

  /* First argument is the status. */
  status = get_status_from_str(smartlist_get(args, 0));
  if (status < 0) {
    goto error;
  }
  dst->status = status;

  /* Second and last argument is the shared random value it self. */
  srv = smartlist_get(args, 1);
  memcpy(dst->value, srv, sizeof(dst->value));
  return 0;

 error:
  return -1;
}

/* Parse the SharedRandPreviousValue line from the state. Return 0 on
 * success else -1. */
static int
disk_state_parse_previous_srv(sr_state_t *state,
                              sr_disk_state_t *disk_state)
{
  config_line_t *line = disk_state->SharedRandPreviousValue;
  tor_assert(!strcasecmp(line->key, dstate_prev_srv_key));
  if (line->value == NULL) {
    return 0;
  }
  state->previous_srv = tor_malloc_zero(sizeof(*state->previous_srv));
  return disk_state_parse_srv(line->value, state->previous_srv);
}

/* Parse the SharedRandCurrentValue line from the state. Return 0 on success
 * else -1. */
static int
disk_state_parse_current_srv(sr_state_t *state,
                             sr_disk_state_t *disk_state)
{
  config_line_t *line = disk_state->SharedRandCurrentValue;
  tor_assert(!strcasecmp(line->key, dstate_cur_srv_key));
  if (line->value == NULL) {
    return 0;
  }
  state->current_srv = tor_malloc_zero(sizeof(*state->current_srv));
  return disk_state_parse_srv(line->value, state->current_srv);
}

/* Parse the given disk state and set a newly allocated state. On success,
 * return that state else NULL. */
static sr_state_t *
disk_state_parse(sr_disk_state_t *new_disk_state)
{
  sr_state_t *new_state = state_new(default_fname);

  tor_assert(new_disk_state);

  new_state->version = new_disk_state->Version;
  new_state->valid_until = new_disk_state->ValidUntil;
  (void) get_phase_from_str;

  /* Parse the shared random values. */
  if (disk_state_parse_previous_srv(new_state, new_disk_state) < 0) {
    goto error;
  }
  if (disk_state_parse_current_srv(new_state, new_disk_state) < 0) {
    goto error;
  }
  /* Parse the commits. */
  if (disk_state_parse_commits(new_state, new_disk_state) < 0) {
    goto error;
  }
  /* Parse the conflicts. */
  if (disk_state_parse_conflicts(new_state, new_disk_state) < 0) {
    goto error;
  }
  /* Great! This new state contains everything we had on disk. */
  return new_state;
error:
  state_free(new_state);
  return NULL;
}

/* Encode a reveal element using a given commit object to dst which is a
 * buffer large enough to put the base64-encoded reveal construction. The
 * format is as follow:
 *     REVEAL = base64-encode( TIMESTAMP || RN )
 * Return 0 on success else a negative value.
 */
STATIC int
reveal_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset;
  char buf[SR_REVEAL_LEN];

  tor_assert(commit);
  tor_assert(dst);

  memset(buf, 0, sizeof(buf));

  set_uint64(buf, tor_htonll((uint64_t) commit->reveal_ts));
  offset = sizeof(commit->reveal_ts);
  memcpy(buf + offset, commit->random_number,
         sizeof(commit->random_number));
  /* Let's clean the buffer and then encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Encode the given commit object to dst which is a buffer large enough to
 * put the base64-encoded commit. The format is as follow:
 *     COMMIT = base64-encode( TIMESTAMP || H(REVEAL) || SIGNATURE )
 */
STATIC int
commit_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset;
  char buf[SR_COMMIT_LEN];

  tor_assert(commit);
  tor_assert(dst);

  memset(buf, 0, sizeof(buf));
  /* First is the timestamp. */
  set_uint64(buf, tor_htonll((uint64_t) commit->commit_ts));
  /* The hash of the reveal is next. */
  offset = sizeof(commit->commit_ts);
  memcpy(buf + offset, commit->hashed_reveal,
         sizeof(commit->hashed_reveal));
  /* Finally, the signature. */
  offset += sizeof(commit->hashed_reveal);
  memcpy(buf + offset, commit->commit_signature.sig,
         sizeof(commit->commit_signature.sig));
  /* Let's clean the buffer and then encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* From a valid conflict object and an allocated config line, set the line's
 * value to the state string representation of a conflict. */
static void
disk_state_put_conflict_line(sr_conflict_commit_t *conflict,
                             config_line_t *line)
{
  int ret;
  char ed_b64[BASE64_DIGEST256_LEN + 1];
  char commit1_b64[SR_COMMIT_BASE64_LEN + 1];
  char commit2_b64[SR_COMMIT_BASE64_LEN + 1];

  tor_assert(conflict);
  tor_assert(line);

  ret = ed25519_public_to_base64(ed_b64, &conflict->auth_identity);
  tor_assert(!ret);
  ret = commit_encode(conflict->commit1, commit1_b64, sizeof(commit1_b64));
  tor_assert(ret);
  ret = commit_encode(conflict->commit2, commit2_b64, sizeof(commit2_b64));
  tor_assert(ret);
  /* We can construct a reveal string if the random number exists meaning
   * it's ours or we got it during the reveal phase. */
  tor_asprintf(&line->value, "%s %s %s %s",
               dstate_conflict_key,
               ed_b64,
               commit1_b64,
               commit2_b64);
}

/* From a valid commit object and an allocated config line, set the line's
 * value to the state string representation of a commit. */
static void
disk_state_put_commit_line(sr_commit_t *commit, config_line_t *line)
{
  int ret;
  char commit_b64[SR_COMMIT_BASE64_LEN + 1];
  /* Add an extra bytes for a whitespace in front to make sure we have the
   * proper disk state format. */
  char reveal_b64[SR_REVEAL_BASE64_LEN + 2];
  memset(reveal_b64, 0, sizeof(reveal_b64));

  tor_assert(commit);
  tor_assert(line);

  ret = commit_encode(commit, commit_b64, sizeof(commit_b64));
  tor_assert(ret);
  /* We can construct a reveal string if the random number exists meaning
   * it's ours or we got it during the reveal phase. */
  if (tor_mem_is_zero((const char *) commit->random_number,
                      sizeof(commit->random_number))) {
    /* First char is a whitespace so we are next to the commit value. */
    reveal_b64[0] = ' ';
    reveal_encode(commit, reveal_b64 + 1, sizeof(reveal_b64) - 1);
  }
  tor_asprintf(&line->value, "%s %s %s %s %s%s",
               dstate_commit_key,
               crypto_digest_algorithm_get_name(commit->alg),
               commit->auth_fingerprint,
               commit->has_majority ? "1" : "0",
               commit_b64,
               reveal_b64);
}

/* From a valid srv object and an allocated config line, set the line's
 * value to the state string representation of a shared random value. */
static void
disk_state_put_srv_line(sr_srv_t *srv, config_line_t *line)
{
  tor_assert(srv);
  tor_assert(line);

  tor_asprintf(&line->value, "%s %s %s",
               line->key,
               get_srv_status_str(srv->status),
               (const char *) srv->value);
}

/* Reset disk state that is free allocated memory and zeroed the object. */
static void
disk_state_reset(void)
{
  config_free_lines(sr_disk_state->Commitments);
  config_free_lines(sr_disk_state->Conflicts);
  config_free_lines(sr_disk_state->SharedRandPreviousValue);
  config_free_lines(sr_disk_state->SharedRandCurrentValue);
  config_free_lines(sr_disk_state->ExtraLines);
  tor_free(sr_disk_state->ProtocolPhase);
  sr_disk_state->ProtocolPhase = NULL;
  memset(sr_disk_state, 0, sizeof(*sr_disk_state));
  sr_disk_state->magic_ = SR_DISK_STATE_MAGIC;
}

/* Update our disk state from our global state. */
static void
disk_state_update(void)
{
  config_line_t **next, *line;

  tor_assert(sr_disk_state);
  tor_assert(sr_state);

  /* Reset current disk state. */
  disk_state_reset();

  /* First, update elements that we don't need to iterate over a list to
   * construct something. */
  sr_disk_state->Version = sr_state->version;
  sr_disk_state->ValidUntil = sr_state->valid_until;
  sr_disk_state->ProtocolPhase = tor_strdup(get_phase_str(sr_state->phase));

  /* Shared random values. */
  line = sr_disk_state->SharedRandPreviousValue =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_prev_srv_key);
  sr_state->previous_srv = tor_malloc_zero(sizeof(*sr_state->previous_srv));
  disk_state_put_srv_line(sr_state->previous_srv, line);
  line = sr_disk_state->SharedRandCurrentValue =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_cur_srv_key);
  sr_state->current_srv = tor_malloc_zero(sizeof(*sr_state->current_srv));
  disk_state_put_srv_line(sr_state->current_srv, line);

  /* Parse the commitments and construct config line(s). */
  next = &sr_disk_state->Commitments;
  DIGEST256MAP_FOREACH(sr_state->commitments, key, sr_commit_t *, commit) {
    *next = line = tor_malloc_zero(sizeof(*line));
    line->key = tor_strdup(dstate_commit_key);
    disk_state_put_commit_line(commit, line);
    next = &(line->next);
  } DIGEST256MAP_FOREACH_END;

  /* Parse the conflict and construct config line(s). */
  next = &sr_disk_state->Conflicts;
  DIGEST256MAP_FOREACH(sr_state->conflicts, key,
                       sr_conflict_commit_t *, conflict) {
    *next = line = tor_malloc_zero(sizeof(*line));
    line->key = tor_strdup(dstate_conflict_key);
    disk_state_put_conflict_line(conflict, line);
    next = &(line->next);
  } DIGEST256MAP_FOREACH_END;
}

/* Load state from disk and put it into our disk state. If the state passes
 * validation, our global state will be updated with it. Return 0 on
 * success. On error, -EINVAL is returned if the state on disk did contained
 * something malformed or is unreadable. -ENOENT is returned indicating that
 * the state file is either empty of non existing. */
static int
disk_state_load_from_disk(void)
{
  int ret;
  char *fname;
  sr_state_t *parsed_state = NULL;
  sr_disk_state_t *disk_state = NULL;

  fname = get_datadir_fname(default_fname);
  switch (file_status(fname)) {
  case FN_FILE:
  {
    config_line_t *lines = NULL;
    char *errmsg = NULL, *content;

    /* Every error in this code path will return EINVAL. */
    ret = -EINVAL;
    disk_state = disk_state_new();

    /* Read content of file so we can parse it. */
    if ((content = read_file_to_str(fname, 0, NULL)) == NULL) {
      log_warn(LD_FS, "Unable to read SR state file \"%s\"", fname);
      goto error;
    }
    if (config_get_lines(content, &lines, 0) < 0) {
      goto error;
    }
    config_assign(&state_format, disk_state, lines, 0, 0, &errmsg);
    config_free_lines(lines);
    if (errmsg) {
      log_warn(LD_GENERAL, "%s", errmsg);
      tor_free(errmsg);
      goto error;
    }
    /* Success, we have populated our disk_state, break and we'll validate
     * it now before returning it. */
    break;
  }
  case FN_NOENT:
  case FN_EMPTY:
    /* Not found or empty, consider this an error which will indicate the
     * caller to save the state to disk. */
    ret = -ENOENT;
    goto error;
  case FN_ERROR:
  case FN_DIR:
  default:
    log_warn(LD_FS, "SR state file \"%s\" not a file? Failing.", fname);
    ret = -EINVAL;
    goto error;
  }

  /* So far so good, we've loaded our state file into our disk state. Let's
   * validate it and then parse it. */
  if (disk_state_validate(disk_state) < 0) {
    ret = -EINVAL;
    goto error;
  }

  parsed_state = disk_state_parse(disk_state);
  if (parsed_state == NULL) {
    disk_state_free(disk_state);
    ret = -EINVAL;
    goto error;
  }
  state_set(parsed_state);
  disk_state_set(disk_state);
  log_notice(LD_DIR, "[SR] State loaded from \"%s\"", fname);
  return 0;
error:
  return ret;
}

/* Save the disk state to disk but before that update it from the current
 * state so we always have the latest. Return 0 on success else -1. */
static int
disk_state_save_to_disk(void)
{
  int ret;
  char *state, *content, *fname;
  char tbuf[ISO_TIME_LEN + 1];
  time_t now = time(NULL);

  tor_assert(sr_disk_state);

  /* Make sure that our disk state is up to date with our memory state
   * before saving it to disk. */
  disk_state_update();
  state = config_dump(&state_format, NULL, sr_disk_state, 0, 0);
  format_local_iso_time(tbuf, now);
  tor_asprintf(&content,
               "# Tor shared random state file last generated on %s "
               "local time\n"
               "# Other times below are in UTC\n"
               "# You *do not* edit this file.\n\n%s",
               tbuf, state);
  tor_free(state);
  fname = get_datadir_fname(default_fname);
  if (write_str_to_file(fname, content, 0) < 0) {
    log_warn(LD_FS, "Unable to write SR state to file \"%s\"", fname);
    ret = -1;
    goto done;
  }
  ret = 0;
  log_info(LD_GENERAL, "Saved SR state to \"%s\"", fname);

done:
  tor_free(fname);
  tor_free(content);
  return ret;
}

/* Cleanup both our global state and disk state. */
static void
sr_cleanup(void)
{
  state_free(sr_state);
  disk_state_free(sr_disk_state);
  /* Nullify our global state. */
  sr_state = NULL;
  sr_disk_state = NULL;
}

/* Initialize shared random subsystem. This MUST be call early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  int ret;

  /* We shouldn't have those assigned. */
  tor_assert(sr_disk_state == NULL);
  tor_assert(sr_state == NULL);

  /* First, we have to try to load the state from disk. */
  ret = disk_state_load_from_disk();
  if (ret < 0) {
    switch (-ret) {
    case ENOENT:
    {
      /* No state on disk so allocate our states for the first time. */
      sr_state_t *new_state = state_new(default_fname);
      sr_disk_state_t *new_disk_state = disk_state_new();
      state_set(new_state);
      /* It's important to set the global disk state pointer since the save
       * call will use a lot of functions that need to query it. */
      disk_state_set(new_disk_state);
      /* No entry, let's save our new state to disk. */
      if (save_to_disk && disk_state_save_to_disk() < 0) {
        sr_cleanup();
        goto error;
      }
      break;
    }
    case EINVAL:
      goto error;
    default:
      /* Big problem. Not possible. */
      tor_assert(0);
    }
  }
  return 0;
error:
  return -1;
}

/* Save our state to disk and cleanup everything. */
void
sr_save_and_cleanup(void)
{
  disk_state_save_to_disk();
  sr_cleanup();
}

/** Generate the commitment/reveal value for the protocol run starting
 *  at <b>timestamp</b>. If <b>my_cert</b> is provided use it as our
 *  authority certificate (used in unittests). */
STATIC sr_commit_t *
generate_sr_commitment(time_t timestamp)
{
  sr_commit_t *commit;
  const ed25519_keypair_t *signing_keypair;

  /* XXX We are currently using our relay identity. In the future we
   * should be using our shared random ed25519 key derived from the
   * authority signing key. */
  signing_keypair = get_master_signing_keypair();
  tor_assert(signing_keypair);

  /* New commit with our identity key. */
  commit = commit_new(&signing_keypair->pubkey);

  /* Generate the reveal random value */
  if (crypto_rand((char *) commit->random_number,
                  sizeof(commit->random_number)) < 0) {
    log_err(LD_REND, "[SR] Unable to generate reveal random value!");
    goto error;
  }
  commit->commit_ts = commit->reveal_ts = timestamp;

  /* Now get the base64 blob that corresponds to our reveal */
  if (reveal_encode(commit, commit->encoded_reveal,
                    sizeof(commit->encoded_reveal)) < 0) {
    log_err(LD_REND, "[SR] Unable to encode the reveal value!");
    goto error;
  }

  /* Now let's create the commitment */

  switch (commit->alg) {
  case DIGEST_SHA1:
    tor_assert(0);
  case DIGEST_SHA256:
    /* Only sha256 is supported and the default. */
  default:
    if (crypto_digest256(commit->hashed_reveal, commit->encoded_reveal,
                         sizeof(commit->encoded_reveal),
                         DIGEST_SHA256) < 0) {
      goto error;
    }
    break;
  }

  { /* Now create the commit signature */
    uint8_t sig_msg[SR_COMMIT_SIG_BODY_LEN];

    memcpy(sig_msg, commit->hashed_reveal, sizeof(commit->hashed_reveal));
    set_uint64(sig_msg + sizeof(commit->hashed_reveal),
               tor_htonll((uint64_t) commit->commit_ts));

    if (ed25519_sign(&commit->commit_signature, sig_msg, sizeof(sig_msg),
                     signing_keypair) < 0) {
      log_warn(LD_BUG, "[SR] Can't sign commitment!");
      goto error;
    }
  }

  /* Now get the base64 blob that corresponds to our commit. */
  if (commit_encode(commit, commit->encoded_commit,
                    sizeof(commit->encoded_commit)) < 0) {
    log_err(LD_REND, "[SR] Unable to encode the commit value!");
    goto error;
  }

  /* This is _our_ commit so it's authoritative. */
  commit->is_authoritative = 1;

  log_warn(LD_GENERAL, "[SR] Generated commitment:");
  commit_log(commit);
  return commit;

 error:
  commit_free(commit);
  return NULL;
}

#if 0
/** Generate the commitment/reveal value for the protocol run starting at
 *  <b>timestamp</b>. */
static sr_commit_t *
generate_sr_commitment_stupid(time_t timestamp)
{
  authority_cert_t *my_cert;
  char fingerprint[FINGERPRINT_LEN+1];
  sr_commit_t *commit = tor_malloc_zero(sizeof(sr_commit_t));
  int commitment, reveal;

  (void) timestamp;

  if (!(my_cert = get_my_v3_authority_cert())) {
    log_warn(LD_DIR, "Can't generate consensus without a certificate.");
    return NULL; /* XXX error mgmt */
  }
  if (crypto_pk_get_fingerprint(my_cert->identity_key,
                                fingerprint, 0) < 0) {
    log_err(LD_GENERAL,"Error computing fingerprint");
    return NULL; /* XXX error mgmt */
  }

  /* This commitment belongs to us! Set our fingerprint. */
  commit->auth_fingerprint = tor_strdup(fingerprint);
  /* Also set our digest */
  crypto_pk_get_digest(my_cert->identity_key, (char *)commit->auth_digest);

  commitment = crypto_rand_int(100);
  reveal = crypto_rand_int(100);

  tor_asprintf(&commit->commitment, "%d", commitment);
  tor_asprintf(&commit->reveal, "%d", reveal);

  /* This is _our_ commit so it's authoritative. */
  commit->is_authoritative = 1;

  log_warn(LD_GENERAL, "[SR] Generated commitment: %d / %d (identity: %s)",
           commitment, reveal, fingerprint);

  return commit;
}
#endif

/* Return commit object from the given authority digest <b>identity</b>.
 * Return NULL if not found. */
static sr_commit_t *
get_commit_from_state(const ed25519_public_key_t *identity)
{
  tor_assert(identity);
  return digest256map_get(sr_state->commitments, identity->pubkey);
}

/* Return conflict object from the given authority digest <b>identity</b>.
 * Return NULL if not found. */
static sr_conflict_commit_t *
get_conflict_from_state(const ed25519_public_key_t *identity)
{
  tor_assert(identity);
  return digest256map_get(sr_state->conflicts, identity->pubkey);
}

/* Add a conflict to the state using the different commits <b>c1</b> and
 * <b>c2</b>. If a conflict already exists, update it with those values. */
static void
add_conflict_to_sr_state(sr_commit_t *c1, sr_commit_t *c2)
{
  sr_conflict_commit_t *conflict, *prev_conflict;

  tor_assert(c1);
  tor_assert(c2);

  /* It's possible to add a conflict for an authority that already has a
   * conflict in our state so we update the entry with the latest one. */
  conflict = conflict_commit_new(c1, c2);
  prev_conflict = digest256map_set(sr_state->conflicts,
                                   conflict->auth_identity.pubkey,
                                   conflict);
  if (prev_conflict != conflict) {
    conflict_commit_free(prev_conflict);
  }
}

/* Add <b>commit</b> to the permanent state. Make sure there are no
 * conflicts. The given commit is duped so the caller should free the memory
 * if needed upon return. */
static void
add_commit_to_sr_state(sr_commit_t *commit)
{
  sr_commit_t *saved_commit = NULL, *dup_commit;

  tor_assert(sr_state);
  tor_assert(commit);

  saved_commit = get_commit_from_state(&commit->auth_identity);
  if (saved_commit != NULL) {
    /* MUST be same pointer else there is a code flow issue. */
    tor_assert(saved_commit == commit);
    return;
  }

  dup_commit = commit_dup(commit);
  digest256map_set(sr_state->commitments, commit->auth_identity.pubkey,
                   dup_commit);

  log_warn(LD_GENERAL, "[SR] \t \t Commit from %s (%s) has been added. "
           "It's %sauthoritative and has %smajority",
           dup_commit->auth_fingerprint, dup_commit->encoded_commit,
           dup_commit->is_authoritative ? "" : "NOT ",
           dup_commit->has_majority ? "" : "NO ");
}

/* Using <b>commit</b>, return a newly allocated string containing the
 * authority identity fingerprint concatenated with its encoded reveal
 * value. It's the caller responsibility to free the memory. This can't fail
 * thus a valid string is always returned. */
static char *
get_srv_element_from_commit(const sr_commit_t *commit)
{
  char *element;
  tor_assert(commit);
  tor_asprintf(&element, "%s%s", commit->auth_fingerprint,
               commit->encoded_reveal);
  return element;
}

/* Return a srv object that is built with the construction:
 *    SRV = HMAC(HASHED_REVEALS, "shared-random" | INT_8(reveal_num) |
 *                               INT_8(version) | previous_SRV)
 * This function cannot fail. */
static sr_srv_t *
generate_srv(const char *hashed_reveals, uint8_t reveal_num)
{
  char msg[SR_SRV_HMAC_MSG_LEN];
  size_t offset = 0;
  sr_srv_t *srv;

  tor_assert(hashed_reveals);
  /* Specification requires at least 3 authorities are needed. */
  tor_assert(reveal_num >= 3);

  /* Add the invariant token. */
  memcpy(msg, SR_SRV_TOKEN, SR_SRV_TOKEN_LEN);
  offset += SR_SRV_TOKEN_LEN;
  set_uint8(msg + offset, reveal_num);
  offset += sizeof(uint8_t);
  set_uint8(msg + offset, SR_PROTO_VERSION);
  offset += sizeof(uint8_t);
  if (sr_state->previous_srv != NULL) {
    memcpy(msg + offset, sr_state->previous_srv->value,
           sizeof(sr_state->previous_srv->value));
  }

  /* Ok we have our message and key for the HMAC computation, allocate our
   * srv object and do the last step. */
  srv = tor_malloc_zero(sizeof(*srv));
  crypto_hmac_sha256((char *) srv->value,
                     hashed_reveals, strlen(hashed_reveals),
                     msg, sizeof(msg));
  srv->status = SR_SRV_STATUS_FRESH;
  return srv;
}

/* Return a srv object that constructed with the disaster mode
 * specification. It's as follow:
 *    HMAC(previous_SRV, "shared-random-disaster")
 * This function cannot fail. */
static sr_srv_t *
generate_srv_disaster(void)
{
  sr_srv_t *srv = tor_malloc_zero(sizeof(*srv));
  static const char *invariant = "shared-random-disaster";

  crypto_hmac_sha256((char *) srv->value,
                     (const char *) sr_state->previous_srv->value,
                     sizeof(sr_state->previous_srv->value),
                     invariant, strlen(invariant));
  srv->status = SR_SRV_STATUS_NONFRESH;
  return srv;
}

/** Compute the shared random value based on the reveals we have. */
static void
compute_shared_random_value(void)
{
  size_t reveal_num;
  char *reveals = NULL;
  smartlist_t *chunks, *commits;

  log_warn(LD_GENERAL, "[SR] Computing SRV");

  /* Computing a shared random value in the commit phase is very wrong. This
   * should only happen at the very end of the reveal phase when a new
   * protocol run is about to start. */
  tor_assert(sr_state->phase == SR_PHASE_REVEAL);

  /* XXX: Let's make sure those conditions to compute an SRV are solid and
   * cover all cases. While writing this I'm still unsure of those. */
  reveal_num = digest256map_size(sr_state->commitments);
  tor_assert(reveal_num < UINT8_MAX);
  /* No reveal values means that we are booting up in the reveal phase thus
   * we shouldn't try to compute a shared random value. */
  if (reveal_num == 0) {
    goto end;
  }
  /* Make sure we have enough reveal values and if not, generate the
   * disaster srv value and stop right away. */
  if (reveal_num < SR_SRV_MIN_REVEAL) {
    sr_state->current_srv = generate_srv_disaster();
    goto end;
  }

  commits = smartlist_new();
  chunks = smartlist_new();

  /* We must make a list of commit ordered by authority fingerprint in
   * ascending order as specified by proposal 250. */
  DIGEST256MAP_FOREACH(sr_state->commitments, key, sr_commit_t *, c) {
    smartlist_add(commits, c);
  } DIGEST256MAP_FOREACH_END;
  smartlist_sort_strings(commits);

  /* Now for each commit, we'll build the element for each authority that
   * needs to go into the srv computation. */
  SMARTLIST_FOREACH_BEGIN(commits, const sr_commit_t *, c) {
    char *element = get_srv_element_from_commit(c);
    smartlist_add(chunks, element);
  } SMARTLIST_FOREACH_END(c);
  smartlist_free(commits);

  {
    /* Make the HMAC-SHA256 computation. */
    char hashed_reveals[DIGEST256_LEN];
    reveals = smartlist_join_strings(chunks, "", 0, NULL);
    SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
    smartlist_free(chunks);
    if (crypto_digest256(hashed_reveals, reveals, strlen(reveals),
                         DIGEST_SHA256) < 0) {
      log_warn(LD_DIR, "[SR] Unable to hash the reveals. Stopping.");
      goto end;
    }
    sr_state->current_srv = generate_srv(hashed_reveals,
                                         (uint8_t) reveal_num);
  }

 end:
  tor_free(reveals);
}

/** This is the first round of the new protocol run starting at
 *  <b>valid_after</b>. Do the necessary housekeeping. */
static void
state_new_protocol_run(time_t valid_after)
{
  sr_commit_t *our_commitment = NULL;

  /* Only compute the srv at the end of the reveal phase. */
  if (sr_state->phase == SR_PHASE_REVEAL) {
    /* We are about to compute a new shared random value that will be set in
     * our state as the current value so swap the current to the previous
     * value right now. */
    tor_free(sr_state->previous_srv);
    sr_state->previous_srv = sr_state->current_srv;
    sr_state->current_srv = NULL;
    /* Compute the shared randomness value of the day. */
    compute_shared_random_value();
  }

  /* Keep counters in track */
  sr_state->n_reveal_rounds = 0;
  sr_state->n_commit_rounds = 0;
  sr_state->n_protocol_runs++;

  /* Do some logging */
  log_warn(LD_GENERAL, "[SR] =========================");
  log_warn(LD_GENERAL, "[SR] Protocol run #%u starting!",
           sr_state->n_protocol_runs);

  /* Wipe old commit/reveal values */
  DIGEST256MAP_FOREACH_MODIFY(sr_state->commitments, key, sr_commit_t *, c) {
    commit_free(c);
    MAP_DEL_CURRENT(key);
  } DIGEST256MAP_FOREACH_END;
  /* Wipe old conflicts */
  DIGEST256MAP_FOREACH_MODIFY(sr_state->conflicts, key,
                              sr_conflict_commit_t *, c) {
    conflict_commit_free(c);
    MAP_DEL_CURRENT(key);
  } DIGEST256MAP_FOREACH_END;

  /* Generate fresh commitments for this protocol run */
  our_commitment = generate_sr_commitment(valid_after);
  if (our_commitment) {
    /* Add our commitment to our state. In case we are unable to create one
     * (highly unlikely), we won't vote for this protocol run since our
     * commitment won't be in our state. */
    add_commit_to_sr_state(our_commitment);
  }
}

/* Transition from the commit phase to the reveal phase by sanitizing our
 * state and making sure it's coherent to get in the reveal phase. */
static void
state_reveal_phase_transition(void)
{
  tor_assert(sr_state->phase == SR_PHASE_REVEAL);
  tor_assert(sr_state->n_reveal_rounds == 0);

  /* Remove commitments that don't have majority. */
  DIGEST256MAP_FOREACH_MODIFY(sr_state->commitments, key,
                           sr_commit_t *, commit) {
    sr_conflict_commit_t *conflict;

    if (!commit->has_majority) {
      commit_free(commit);
      MAP_DEL_CURRENT(key);
      /* Commit is out, we are done here. */
      continue;
    }
    /* Safety net, we shouldn't have a commit from an authority that also
     * has a conflict for the same authority. If so, this is a BUG so log it
     * and clean it. */
    conflict = get_conflict_from_state(&commit->auth_identity);
    if (conflict != NULL) {
      log_warn(LD_DIR, "[SR] BUG: Commit found for authority %s "
                       "but we have a conflict for this authority.",
               commit->auth_fingerprint);
      commit_free(commit);
      MAP_DEL_CURRENT(key);
    }
  } DIGEST256MAP_FOREACH_END;
}

/* Return 1 iff the <b>next_phase</b> is a phase transition from the current
 * phase that is it's different. */
static int
is_phase_transition(sr_phase_t next_phase)
{
  return sr_state->phase != next_phase;
}

/* Update the current SR state as needed for the upcoming voting round at
 * <b>valid_after</b>. Don't call this function twice in the same voting
 * period. */
static void
update_state(time_t valid_after)
{
  tor_assert(sr_state);

  /* Get the new protocol phase according to the current hour */
  sr_phase_t new_phase = get_sr_protocol_phase(valid_after);

  /* Are we in a phase transition that is the next phase is not the same as
   * the current one? */
  if (is_phase_transition(new_phase)) {
    switch (new_phase) {
    case SR_PHASE_COMMIT:
      /* We were in the reveal phase or we are just starting so this is a
       * new protocol run. */
      state_new_protocol_run(valid_after);
      break;
    case SR_PHASE_REVEAL:
      /* We were in the commit phase thus now in reveal. */
      state_reveal_phase_transition();
      break;
    }
    /* Set the new phase for this round */
    sr_state->phase = new_phase;
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

  /* Everything is up to date in our state, make sure our permanent disk
   * state is also updated and written to disk. */
  disk_state_save_to_disk();

  { /* Some logging. */
    char tbuf[ISO_TIME_LEN + 1];
    format_iso_time(tbuf, valid_after);
    log_warn(LD_DIR, "[SR] ------------------------------");
    log_warn(LD_DIR, "[SR] State prepared for new voting round (%s). "
             "Current phase is %s (%d/%d).",
             tbuf, get_phase_str(sr_state->phase),
             sr_state->n_commit_rounds, sr_state->n_reveal_rounds);
  }
}

/** Given <b>commit</b> give the line that we should place in our votes.
 * It's the responsibility of the caller to free the string. */
static char *
get_vote_line_from_commit(const sr_commit_t *commit)
{
  char *vote_line = NULL;
  sr_phase_t current_phase = sr_state->phase;
  static const char *commit_str_key = "shared-rand-commitment";

  switch (current_phase) {
  case SR_PHASE_COMMIT:
    tor_asprintf(&vote_line, "%s %s %s %s\n",
                 commit_str_key,
                 commit->auth_fingerprint,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->encoded_commit);
    break;
  case SR_PHASE_REVEAL:
  {
    /* Send a reveal value for this commit if we have one. */
    const char *reveal_str = commit->encoded_reveal;
    if (tor_mem_is_zero(commit->encoded_reveal,
                        sizeof(commit->encoded_reveal))) {
      reveal_str = "";
    }
    tor_asprintf(&vote_line, "%s %s %s %s %s\n",
                 commit_str_key,
                 commit->auth_fingerprint,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->encoded_commit, reveal_str);
    break;
  }
  default:
    tor_assert(0);
  }

  return vote_line;
}

/* Given <b>conflict</b> give the line that we should place in our votes.
 * It's the responsibility of the caller to free the string. */
static char *
get_vote_line_from_conflict(const sr_conflict_commit_t *conflict)
{
  char *line = NULL;
  static const char *conflict_str_key = "shared-rand-conflict";

  tor_assert(conflict);

  tor_asprintf(&line, "%s %s %s %s\n",
               conflict_str_key,
               conflict->commit1->auth_fingerprint,
               conflict->commit1->encoded_commit,
               conflict->commit2->encoded_commit);
  return line;
}

/* Return a smartlist for which each element is the SRV line that should be
 * put in a vote or consensus. Caller must free the string elements in the
 * list once done with it. */
static smartlist_t *
get_srv_vote_line(void)
{
  char *srv_line = NULL;
  char srv_hash_encoded[HEX_DIGEST256_LEN + 1];
  smartlist_t *lines = smartlist_new();
  sr_srv_t *srv;
  static const char *prev_str_key = "shared-rand-previous-value";
  static const char *cur_str_key = "shared-rand-current-value";

  /* Compute the previous srv value if one. */
  srv = sr_state->previous_srv;
  if (srv != NULL) {
    base16_encode(srv_hash_encoded, sizeof(srv_hash_encoded),
                  (const char *) srv->value, sizeof(srv->value));
    tor_asprintf(&srv_line, "%s %s %s\n", prev_str_key,
                 get_srv_status_str(srv->status), srv_hash_encoded);
    smartlist_add(lines, srv_line);
    log_warn(LD_DIR, "[SR] \t Previous SRV: %s", srv_line);
  }
  /* Compute current srv value if one. */
  srv = sr_state->current_srv;
  if (srv != NULL) {
    base16_encode(srv_hash_encoded, sizeof(srv_hash_encoded),
                  (const char *) srv->value, sizeof(srv->value));
    tor_asprintf(&srv_line, "%s %s %s\n", cur_str_key,
                 get_srv_status_str(srv->status), srv_hash_encoded);
    smartlist_add(lines, srv_line);
    log_warn(LD_DIR, "[SR] \t Current SRV: %s", srv_line);
  }
  return lines;
}

/* Return a heap-allocated string that should be put in the votes and
 * contains the shared randomness information for this phase. It's the
 * responsibility of the caller to free the string. */
char *
sr_get_string_for_vote(void)
{
  char *vote_str = NULL;
  smartlist_t *chunks = smartlist_new();

  tor_assert(sr_state);

  log_warn(LD_GENERAL, "[SR] Sending out vote string:");

  /* In our vote we include every commitment in our permanent state. */
  DIGEST256MAP_FOREACH(sr_state->commitments, key,
                       const sr_commit_t *, commit) {
    char *line = get_vote_line_from_commit(commit);
    smartlist_add(chunks, line);
    log_warn(LD_DIR, "[SR] \t Commit: %s", line);
  } DIGEST256MAP_FOREACH_END;

  /* Add conflict(s) to our vote. */
  DIGEST256MAP_FOREACH(sr_state->conflicts, key,
                       const sr_conflict_commit_t *, conflict) {
    char *line = get_vote_line_from_conflict(conflict);
    smartlist_add(chunks, line);
    log_warn(LD_DIR, "[SR] \t Conflict: %s", line);
  } DIGEST256MAP_FOREACH_END;

  /* Add the SRV values to the string. */
  {
    smartlist_t *srv_lines = get_srv_vote_line();
    smartlist_add_all(chunks, srv_lines);
    smartlist_free(srv_lines);
  }

  vote_str = smartlist_join_strings(chunks, "", 0, NULL);
  //SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
  //smartlist_free(chunks);
  log_warn(LD_DIR, "[SR] Our vote string:\n%s\n", vote_str);
  return vote_str;
}

/* Given all the commitment information from a commitment line in a vote,
 * parse the line, validate it and return a newly allocated commit object
 * that contains the verified data from the vote. Return NULL on error. */
sr_commit_t *
sr_handle_received_commitment(const char *commit_pubkey, const char *hash_alg,
                              const char *commitment, const char *reveal)
{
  sr_commit_t *commit;
  smartlist_t *args;

  tor_assert(commit_pubkey);
  tor_assert(hash_alg);
  tor_assert(commitment);

  /* Build a list of arguments that have the same order as the Commitment
   * line in the state. With that, we can parse it using the same function
   * that the state uses. Line format is as follow:
   *    "shared-rand-commitment" SP algname SP identity SP majority SP
   *                             commitment-value [SP revealed-value] NL
   */
  args = smartlist_new();
  smartlist_add(args, (char *) hash_alg);
  smartlist_add(args, (char *) commit_pubkey);
  smartlist_add(args, (char *) "0"); /* Majority field set to 0. */
  smartlist_add(args, (char *) commitment);
  if (reveal != NULL) {
    smartlist_add(args, (char *) reveal);
  }
  /* Parse our arguments to get a commit that we'll then verify. */
  commit = parse_commitment_line(args);
  if (commit == NULL) {
    goto end;
  }
  /* We now have a commit object that has been fully populated by our vote
   * data. Now we'll validate it. This function will make sure also to
   * validate the reveal value if one is present. */
  if (verify_received_commit(commit) < 0) {
    commit_free(commit);
    commit = NULL;
    goto end;
  }

end:
  smartlist_free(args);
  return commit;
}


/* Return 1 iff the two commits have the same commitment values. This
 * function does not care about reveal values. */
static int
commitments_are_the_same(const sr_commit_t *commit_one,
                         const sr_commit_t *commit_two)
{
  tor_assert(commit_one);
  tor_assert(commit_two);

  if (strcmp(commit_one->encoded_commit, commit_two->encoded_commit)) {
    return 0;
  }
  return 1;
}

/* Return True if <b>commit</b> is included in enough <b>votes</b> to be the
 * majority opinion. */
static int
commit_has_majority(const sr_commit_t *commit, smartlist_t *votes)
{
  int n_voters = get_n_authorities(V3_DIRINFO);
  int votes_required_for_majority = (n_voters / 2) + 1;
  int votes_for_this_commit = 0;

  tor_assert(commit);
  tor_assert(votes);

  /* Let's avoid some useless work here. Protect those CPU cycles! */
  if (commit->has_majority) {
    return 1;
  }

  /* Go through all the votes and count the ones that include this commit. */
  SMARTLIST_FOREACH_BEGIN(votes, const networkstatus_t *, v) {
    if (digest256map_get(v->commitments, commit->auth_identity.pubkey)) {
      votes_for_this_commit++;
    }
  } SMARTLIST_FOREACH_END(v);

  log_warn(LD_GENERAL, "[SR] \t \t Commit %s from %s. It has %d votes and it needs %d.",
           commit->encoded_commit, commit->auth_fingerprint,
           votes_for_this_commit, votes_required_for_majority);

  /* Did we reached at least majority ? */
  return votes_for_this_commit >= votes_required_for_majority;
}

#if 0
/* We just received a commit from the vote of authority with
 * <b>identity_digest</b>. Return 1 if this commit is authorititative that
 * is, it belongs to the authority that voted it. Else return 0 if not. */
static int
commit_is_authoritative(const sr_commit_t *commit,
                        const ed25519_public_key_t *identity)
{
  tor_assert(commit);
  tor_assert(identity);

  /* Let's avoid some useless work here. Protect those CPU cycles! */
  if (commit->is_authoritative) {
    return 1;
  }
  return !fast_memcmp(&commit->auth_identity, identity,
                      sizeof(commit->auth_identity));
}
#endif

/* Decide if <b>commit</b> can be added to our state that is check if the
 * commit is authoritative or/and has majority. Return 1 if the commit
 * should be added to our state or 0 if not. */
static int
should_keep_commitment(sr_commit_t *commit,
                       networkstatus_voter_info_t *voter,
                       smartlist_t *votes)
{
  tor_assert(commit);
  tor_assert(voter);
  tor_assert(votes);

  /* For a commit to be added to our state, we need it to match one of the
   * two possible conditions.
   *
   * First, if the commit is authoritative that is it's the voter's commit.
   * The reason to keep it is that we put those authoritative commits in our
   * vote to try to reach majority which is basically telling the world
   * we've seen a commit from a specific authority.
   *
   * Second, if the commit has been seen by the majority of authorities. If
   * so, by consensus, we decided that this commit is usable for our shared
   * random computation and we can then also put it in our vote from that
   * point on. */
  /* XXX: Use ed25519 identity key here of the voter. */
  commit->is_authoritative = 1;
#if 0
  commit->is_authoritative = commit_is_authoritative(commit,
                                                     voter->identity_digest);
#endif
  commit->has_majority = commit_has_majority(commit, votes);

  /* One of those conditions is enough. */
  return commit->is_authoritative | commit->has_majority;
}

/* We are during commit phase and we found <b>commit</b> in a vote of
 * <b>voter_fingerprint</b>. All the other received votes are found in
 * <b>votes</b>. Decide whether we should keep this commit, issue a conflict
 * line, or ignore it. */
static void
decide_commit_during_commit_phase(sr_commit_t *commit,
                                  networkstatus_voter_info_t *voter,
                                  smartlist_t *votes)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(voter);
  tor_assert(votes);
  tor_assert(sr_state->phase == SR_PHASE_COMMIT);

  log_warn(LD_GENERAL, "[SR] \t Deciding commit %s by %s",
           commit->encoded_commit, commit->auth_fingerprint);

  /* Query our state to know if we already have this commit saved. If so,
   * use the saved commit else use the new one. */
  saved_commit = get_commit_from_state(&commit->auth_identity);
  if (saved_commit != NULL) {
    /* They can not be different commits at this point since we've
     * already processed all conflicts. */
    int same_commits = commitments_are_the_same(commit, saved_commit);
    tor_assert(same_commits);
    /* From now on, uses the commit found in our state. */
    commit = saved_commit;
  }

  /* Decide the state of the commit which will tell us if we can add it to
   * our state. This also updates the commit object. */
  if (should_keep_commitment(commit, voter, votes)) {
    /* Let's not add a commit that we already have. */
    if (saved_commit == NULL) {
      add_commit_to_sr_state(commit);
    }
  } else {
    char voter_fp[HEX_DIGEST_LEN + 1];
    base16_encode(voter_fp, sizeof(voter_fp), voter->identity_digest,
                  sizeof(voter->identity_digest));
    log_warn(LD_DIR, "[SR] Commit of authority %s received from %s "
                     "is not authoritative nor has majority. Ignoring.",
             commit->auth_fingerprint, voter_fp);
  }
}

/* We are during commit phase and we found <b>commit</b> in a
 * vote. See if it contains any reveal values that we could use. */
static void
decide_commit_during_reveal_phase(sr_commit_t *commit)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(sr_state->phase == SR_PHASE_REVEAL);

  int have_reveal = !tor_mem_is_zero(commit->encoded_reveal,
                                     sizeof(commit->encoded_reveal));
  log_warn(LD_GENERAL, "[SR] \t Commit %s (%s) by %s",
           commit->encoded_commit,
           have_reveal ? commit->encoded_reveal : "NOREVEAL",
           commit->auth_fingerprint);

  /* If the received commit contains no reveal value, we are not interested
   * in it so ignore. */
  if (!have_reveal) {
    return;
  }

  /* Get the commit from our state. If it's not found, it's possible that we
   * didn't get a commit from the commit phase but we now see the reveal
   * from someone else. In this case, we ignore it since we didn't rule that
   * this commit had majority. */
  saved_commit = get_commit_from_state(&commit->auth_identity);
  if (saved_commit == NULL) {
    return;
  }
  /* They can not be different commits at this point since we've
   * already processed all conflicts. */
  int same_commits = commitments_are_the_same(commit, saved_commit);
  tor_assert(same_commits);

  /* If we already have a commitment by this authority, and our saved
   * commit doesn't have a reveal value, add it. */
  log_warn(LD_GENERAL, "[SR] \t \t Ah, learned reveal %s for commit %s",
           commit->encoded_reveal, commit->encoded_commit);
  memcpy(saved_commit->encoded_reveal, commit->encoded_reveal,
         sizeof(saved_commit->encoded_reveal));
}

/* For all vote in <b>votes</b>, go over the every commitment and check if
 * we already have a commit from the same authority but with a different
 * value in our state and if so add the conflict to the state.  */
static void
decide_conflict_from_votes(const smartlist_t *votes)
{
  tor_assert(votes);

  SMARTLIST_FOREACH_BEGIN(votes, const networkstatus_t *, v) {
    /* No commitments were present in this vote. */
    if (v->commitments == NULL) {
      continue;
    }
    DIGEST256MAP_FOREACH(v->commitments, key, sr_commit_t *, commit) {
      sr_commit_t *saved_commit;

      saved_commit = get_commit_from_state(&commit->auth_identity);
      if (saved_commit == NULL) {
        /* No conflict since we do not have it in our state. Ignore. */
        continue;
      }
      /* Is it a different commit from our state? If yes, add a conflict to
       * the state. */
      if (!commitments_are_the_same(commit, saved_commit)) {
        add_conflict_to_sr_state(commit, saved_commit);
      }
    } DIGEST256MAP_FOREACH_END;
  } SMARTLIST_FOREACH_END (v);
}

/* For all vote in <b>votes</b>, decide if the commitments should be ignored
 * or added/updated to our state. Depending on the phase here, different
 * actions are taken. */
static void
decide_commit_from_votes(sr_phase_t phase, smartlist_t *votes)
{
  tor_assert(votes);
  tor_assert(phase == SR_PHASE_COMMIT || phase == SR_PHASE_REVEAL);

  /* For each votes, check if we need to add it to our state or not. */
  SMARTLIST_FOREACH_BEGIN(votes, const networkstatus_t *, v) {
    networkstatus_voter_info_t *voter = smartlist_get(v->voters, 0);
    /* No commitments were present in this vote. */
    if (v->commitments == NULL) {
      continue;
    }
    /* XXX: Use the ed25519 authority key here. */
#if 0
    /* Ignore authority vote if we have a conflict for it. */
    if (get_conflict_from_state()) {
      continue;
    }
#endif
    /* Go over all commitments and depending on the phase decide what to do
     * with them that is keeping or updating them based on the votes. */
    DIGEST256MAP_FOREACH(v->commitments, key, sr_commit_t *, commit) {
      switch (phase) {
      case SR_PHASE_COMMIT:
        decide_commit_during_commit_phase(commit, voter, votes);
        break;
      case SR_PHASE_REVEAL:
        decide_commit_during_reveal_phase(commit);
        break;
      default:
        tor_assert(0);
      }
    } DIGEST256MAP_FOREACH_END;
  } SMARTLIST_FOREACH_END (v);
}

/** This is called in the end of each voting round. Decide which
 *  commitments/reveals to keep and write them to perm state. */
void
sr_decide_state_post_voting(smartlist_t *votes)
{
  log_warn(LD_GENERAL, "[SR] About to decide state (phase: %s):",
           get_phase_str(sr_state->phase));

  /* First step is to find if we have any conflicts and if so add them to
   * our state. This is important because after that we will decide if we
   * keep the commitments as authoritative or decided by majority from which
   * we MUST exclude conflicts. */
  decide_conflict_from_votes(votes);

   /* Then we decide which commit to keep in our state considering that all
    * conflicts have been found previously. */
  decide_commit_from_votes(sr_state->phase, votes);

  log_warn(LD_GENERAL, "[SR] State decided!");
}

/* Prepare the shared random state we are going to be using for the upcoming
 * voting period at <b>valid_after</b>. This function should be called once at
 * the beginning of each new voting period. */
void
sr_prepare_state_for_new_voting_period(time_t valid_after)
{
  tor_assert(sr_state);

  /* Update the old state with information about this new round */
  update_state(valid_after);
}
