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
get_testing_network_protocol_phase(void)
{
  /* XXX In this function we assume that in a testing network all dirauths
     started together. Otherwise their phases will get desynched!!! */
  tor_assert(sr_state);

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

/* Helper: deallocate a commit object. (Used with digest256map_free(),
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

  tor_assert(c1);
  tor_assert(c2);

  if (identity != NULL) {
    memcpy(conflict->identity, identity, sizeof(conflict->identity));
  }
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
  old = digest256map_set(sr_state->conflicts, conflict->identity, conflict);
  conflict_commit_free(old);
  {
    /* Logging. */
    char ed_b64[BASE64_DIGEST256_LEN + 1];
    digest256_to_base64(ed_b64, (const char *) conflict->identity);
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
  old_commit = digest256map_remove(sr_state->commitments, commit->identity);
  if (old_commit != NULL) {
    /* Create conflict for this authority identity and update the state. */
    sr_conflict_commit_t *conflict =
      conflict_commit_new(commit->identity, old_commit, commit);
    conflict_commit_add(conflict);
  } else {
    char ed_b64[BASE64_DIGEST256_LEN + 1];
    /* Set it in state. */
    digest256map_set(sr_state->commitments, commit->identity, commit);
    /* Logging. */
    digest256_to_base64(ed_b64, (const char *) commit->identity);
    log_info(LD_GENERAL, "Commit from authority %s has been saved.",
             ed_b64);
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
  new_state->commitments_tmp = digestmap_new();
  new_state->conflicts = digest256map_new();
  new_state->phase = SR_PHASE_UNKNOWN;
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

/** DOCDOC Given all the commitment information, register an sr_commit_t. */
/* XXX merge with parse_commitment_line() */
sr_commit_t *
sr_handle_received_commitment(const char *commit_pubkey, const char *hash_alg,
                              const char *commitment, const char *reveal)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(sr_commit_t));
  char digest[DIGEST_LEN];
  digest_algorithm_t alg;

  /* Get the identity fpr of the auth that the commitment belongs to */
  commit->auth_fingerprint = tor_strdup(commit_pubkey);

  /* Now get the identity digest from the hex fpr. */
  if (base16_decode(digest, DIGEST_LEN, commit_pubkey, strlen(commit_pubkey))) {
    log_warn(LD_DIR, "Couldn't decode router fingerprint %s", commit_pubkey);
    return NULL; /* XXX error mgmt */
  }
  memcpy(commit->auth_digest, digest, DIGEST_LEN);

  /* Parse hash algorithm */
  alg = crypto_digest_algorithm_parse_name(hash_alg);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_GENERAL, "Commitment line algorithm is not recognized.");
    return NULL; /* XXX error mgmt */
  }

  tor_asprintf(&commit->commitment, "%s", commitment);

  /* XXX Make sure we don't have commits with reveal values during commit phase */
  /* XXX Make sure we don't have commits with new commit values during reveal phase */

  if (reveal) {
    /* XXX We just received a reveal. Here we need to validate that
       the reveal corresponds with the commit. */
    tor_asprintf(&commit->reveal, "%s", reveal);
  }

  return commit;
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
 *    base64-encode(TIMESTAMP || H(REVEAL) || SIGNATURE)
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
static int
parse_encoded_commit(const char *encoded, sr_commit_t *commit)
{
  int ok;
  uint64_t ts;
  size_t offset;
  char b64_buffer[SR_COMMIT_LEN + 1];

  tor_assert(encoded);
  tor_assert(commit);

  /* Decode our encoded commit. */
  if (base64_decode(b64_buffer, sizeof(b64_buffer),
                    encoded, strlen(encoded)) < 0) {
    log_warn(LD_GENERAL, "Commit can't be bas64-decoded.");
    goto error;
  }

  ts = tor_parse_uint64(b64_buffer, 10, 0, UINT64_MAX, &ok, NULL);
  if (!ok) {
    log_warn(LD_GENERAL, "Commit timestamp is invalid.");
    goto error;
  }
  commit->commit_ts = (time_t) tor_ntohll(ts);
  /* Next is the hash of the reveal value. */
  offset = sizeof(uint64_t);
  memcpy(commit->reveal_hash, b64_buffer + offset,
         sizeof(commit->reveal_hash));
  /* Next is the signature of the commit. */
  offset += sizeof(commit->reveal_hash);
  memcpy(&commit->signature, b64_buffer + offset,
         sizeof(commit->signature));
  return 0;
error:
  return -1;
}

/* Parse a Commitment line from our disk state and return a newly allocated
 * commit object. NULL is returned on error. */
static sr_commit_t *
parse_commitment_line(smartlist_t *args)
{
  int ok;
  char *value, identity[ED25519_PUBKEY_LEN], isotime[ISO_TIME_LEN + 1];
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
  if (digest256_from_base64(identity, value) < 0) {
    log_warn(LD_GENERAL, "Commitment line identity is not recognized.");
    goto error;
  }
  /* Allocate commit since we have a valid identity now. */
  commit = commit_new((uint8_t *) identity);

  /* Third argument is the majority value. 0 or 1. */
  value = smartlist_get(args, 2);
  commit->has_majority = !!strcmp(value, "0");

  /* Fourth and fifth arguments is the ISOTIME. */
  tor_snprintf(isotime, sizeof(isotime), "%s %s",
               (char *) smartlist_get(args, 3),
               (char *) smartlist_get(args, 4));
  if (parse_iso_time(isotime, &commit->received_ts) < 0) {
    log_warn(LD_GENERAL, "Commitment line timestamp is not recognized.");
    goto error;
  }
  /* Sixth argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 5);
  if (parse_encoded_commit(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Seventh argument is the revealed value. */
  value = smartlist_get(args, 6);
  if (value != NULL) {
    uint64_t ts_64;
    time_t ts;
    char b64_buffer[SR_REVEAL_LEN + 1];
    if (base64_decode(b64_buffer, sizeof(b64_buffer),
                      value, strlen(value)) < 0) {
      log_warn(LD_GENERAL, "Commitment line b64 reveal is not recognized.");
      goto error;
    }

    ts_64 = tor_parse_uint64(b64_buffer, 10, 0, UINT64_MAX, &ok, NULL);
    ts = (time_t) tor_ntohll(ts_64);
    if (!ok || ts != commit->commit_ts) {
      log_warn(LD_GENERAL, "Commitment reveal timestamp is invalid.");
      goto error;
    }
    /* Copy the last part, the random value. */
    memcpy(commit->random_number, b64_buffer + sizeof(uint64_t),
           sizeof(commit->random_number));
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
  char *value, identity[ED25519_PUBKEY_LEN];
  sr_commit_t *commit1 = NULL, *commit2 = NULL;
  sr_conflict_commit_t *conflict = NULL;

  /* First argument is the authority identity. */
  value = smartlist_get(args, 0);
  if (digest256_from_base64(identity, value) < 0) {
    log_warn(LD_GENERAL, "Conflict line identity is not recognized.");
    goto error;
  }
  /* Second argument is the first commit value base64-encoded. */
  commit1 = commit_new((uint8_t *) identity);
  value = smartlist_get(args, 5);
  if (parse_encoded_commit(value, commit1) < 0) {
    goto error;
  }
  /* Third argument is the second commit value base64-encoded. */
  commit2 = commit_new((uint8_t *) identity);
  value = smartlist_get(args, 5);
  if (parse_encoded_commit(value, commit2) < 0) {
    goto error;
  }
  /* Everything is parsing correctly, allocate object and return it. */
  conflict = conflict_commit_new((uint8_t *) identity, commit1, commit2);
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
  return disk_state_parse_srv(line->value, &state->previous_srv);
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
  return disk_state_parse_srv(line->value, &state->current_srv);
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
 */
static void
reveal_encode(sr_commit_t *commit, char *dst)
{
  size_t offset;
  char buf[SR_REVEAL_LEN];

  tor_assert(commit);
  tor_assert(dst);

  memset(buf, 0, sizeof(buf));

  set_uint64(buf, tor_htonll((uint64_t) commit->commit_ts));
  offset = sizeof(commit->commit_ts);
  memcpy(buf + offset, commit->random_number,
         sizeof(commit->random_number));
  /* Let's clean the buffer and then encode it. */
  memset(dst, 0, SR_REVEAL_BASE64_LEN);
  base64_encode(dst, SR_REVEAL_BASE64_LEN, buf, sizeof(buf), 0);
}

/* Encode the given commit object to dst which is a buffer large enough to
 * put the base64-encoded commit. The format is as follow:
 *     COMMIT = base64-encode( TIMESTAMP || H(REVEAL) || SIGNATURE )
 */
static void
commit_encode(sr_commit_t *commit, char *dst)
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
  memcpy(buf + offset, commit->reveal_hash, DIGEST256_LEN);
  /* Finally, the signature. */
  offset += DIGEST256_LEN;
  memcpy(buf + offset, &commit->signature, sizeof(commit->signature));

  /* Let's clean the buffer and then encode it. */
  memset(dst, 0, SR_COMMIT_BASE64_LEN);
  base64_encode(dst, SR_COMMIT_BASE64_LEN, buf, sizeof(buf), 0);
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

  ret = digest256_to_base64(ed_b64, (const char *) conflict->identity);
  tor_assert(!ret);
  commit_encode(conflict->commit1, commit1_b64);
  commit_encode(conflict->commit2, commit2_b64);
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
  char ed_b64[BASE64_DIGEST256_LEN + 1];
  char tbuf[ISO_TIME_LEN + 1];
  char commit_b64[SR_COMMIT_BASE64_LEN + 1];
  /* Add an extra bytes for a whitespace in front to make sure we have the
   * proper disk state format. */
  char reveal_b64[SR_REVEAL_BASE64_LEN + 2];
  memset(reveal_b64, 0, sizeof(reveal_b64));

  tor_assert(commit);
  tor_assert(line);

  ret = digest256_to_base64(ed_b64, (const char *) commit->identity);
  tor_assert(!ret);
  format_iso_time(tbuf, commit->commit_ts);
  commit_encode(commit, commit_b64);
  /* We can construct a reveal string if the random number exists meaning
   * it's ours or we got it during the reveal phase. */
  if (tor_mem_is_zero((const char *) commit->random_number,
                      sizeof(commit->random_number))) {
    /* First char is a whitespace so we are next to the commit value. */
    reveal_b64[0] = ' ';
    reveal_encode(commit, reveal_b64 + 1);
  }
  tor_asprintf(&line->value, "%s %s %s %s %s %s%s",
               dstate_commit_key,
               crypto_digest_algorithm_get_name(commit->alg),
               ed_b64,
               commit->has_majority ? "1" : "0",
               tbuf,
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

  /* Shared random values. */
  line = sr_disk_state->SharedRandPreviousValue =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_prev_srv_key);
  disk_state_put_srv_line(&sr_state->previous_srv, line);
  line = sr_disk_state->SharedRandCurrentValue =
    tor_malloc_zero(sizeof(*line));
  line->key = tor_strdup(dstate_cur_srv_key);
  disk_state_put_srv_line(&sr_state->current_srv, line);

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

  return 0; /* XXX tempp to avoid assert */

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

/** Generate the commitment/reveal value for the protocol run starting at
 *  <b>timestamp</b>. */
static sr_commit_t *
generate_sr_commitment(time_t timestamp)
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

  log_warn(LD_GENERAL, "[SR] Generated commitment: %d / %d (identity: %s)",
           commitment, reveal, fingerprint);

  return commit;
}

/** Compute the shared random value based on the reveals we have. */
static void
compute_shared_random_value(void)
{
  int sum = 0; /* XXX */
  int ok;

  /* XXX Don't call this during bootstrap */

  log_warn(LD_GENERAL, "[SR] About to calculate SRV:");

  DIGESTMAP_FOREACH(sr_state->commitments_tmp, key, const sr_commit_t *, commit) {
    if (commit->reveal) {
      int reveal_int =
        (int) tor_parse_long(commit->reveal,10,0,65535,&ok,NULL);

      tor_assert(ok);

      log_warn(LD_GENERAL, "[SR] \t Folding in %d", reveal_int);

      sum += reveal_int;
    }
  } DIGESTMAP_FOREACH_END;

  log_warn(LD_GENERAL, "[SR] \t SRV = %d", sum);
}


/** This is the first round of the new protocol run starting at
 *  <b>valid_after</b>. Do the necessary housekeeping. */
static int
update_state_new_protocol_run(time_t valid_after)
{
  sr_commit_t *our_commitment = NULL;

  /* Compute the shared randomness value of the day. */
  compute_shared_random_value();

  /* Keep counters in track */
  sr_state->n_reveal_rounds = 0;
  sr_state->n_commit_rounds = 0;
  sr_state->n_protocol_runs++;

  /* Do some logging */
  log_warn(LD_GENERAL, "[SR] =========================");
  log_warn(LD_GENERAL, "[SR] Protocol run #%u starting!",
           sr_state->n_protocol_runs);

  /*  Wipe old commit/reveal values */
  digestmap_free(sr_state->commitments_tmp, NULL); /* XXX free commits!!! */
  sr_state->commitments_tmp = digestmap_new();

  /* Generate fresh commitments for this protocol run */
  our_commitment = generate_sr_commitment(valid_after);
  tor_assert(our_commitment); /* XXX check that this can be asserted */
  digestmap_set(sr_state->commitments_tmp, (char *) our_commitment->auth_digest, our_commitment);

  return 1;
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
  tor_assert(new_phase != SR_PHASE_UNKNOWN);

  /* Set the phase of this round */
  sr_state->phase = new_phase;

  /* Check if we are now starting a new protocol run and if yes, do the
   * necessary operations. */
  if (sr_state->phase == SR_PHASE_UNKNOWN ||
      (sr_state->phase == SR_PHASE_REVEAL && new_phase == SR_PHASE_COMMIT)) {
    update_state_new_protocol_run(valid_after);
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

/** Given <b>commit</b> give the line that we should place in our
 *  votes. It's the responsibility of hte caller to free the
 *  string. */
static char *
get_vote_line_from_commit(const sr_commit_t *commit, sr_phase_t current_phase)
{
  char *vote_line = NULL;

  tor_assert(current_phase != SR_PHASE_UNKNOWN);

  if (current_phase == SR_PHASE_COMMIT) {
    tor_asprintf(&vote_line, "shared-rand-commitment %s %s %s\n",
                 commit->auth_fingerprint, "sha256", commit->commitment);
  } else { /* reveal phase */
    /* We are in reveal phase. Send a reveal value for this commit if we have one. */
    const char *reveal_str = commit->reveal ? commit->reveal : "";

    tor_asprintf(&vote_line, "shared-rand-commitment %s %s %s %s\n",
                 commit->auth_fingerprint, "sha256", commit->commitment,
                 reveal_str);
  }

  return vote_line;
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
  DIGESTMAP_FOREACH(sr_state->commitments_tmp, key, const sr_commit_t *, commit) {
    char *commitment_vote_line = get_vote_line_from_commit(commit, sr_state->phase);
    smartlist_add(chunks, commitment_vote_line);
    log_warn(LD_GENERAL, "[SR] \t %s", commitment_vote_line);
  } DIGESTMAP_FOREACH_END;

  /* XXX free chunks */
  vote_str = smartlist_join_strings(chunks, "", 0, NULL);

  return vote_str;
}

/** Return true if we have another commit from the same authority as
 *  <b>commit</b>. */
static sr_commit_t *
get_commit_from_same_auth(const sr_commit_t *commit)
{
  return (sr_commit_t *) digestmap_get(sr_state->commitments_tmp, (char *) commit->auth_digest);
}

static void
add_conflict_to_sr_state(sr_commit_t *commit)
{
  (void) commit;
  return; /* XXX NOP */
}

/** Add <b>commit</b> to the permanent state.  Make sure there are no
 *  conflicts. */
static void
add_commit_to_sr_state(sr_commit_t *commit)
{
  tor_assert(sr_state);

  {
    /* Make sure we are not adding conflicting commits to the state. We
     * don't want to add multiple commit values for a single authority,
     * or add the same commit value many times. */
    sr_commit_t *saved_commit = get_commit_from_same_auth(commit);
    if (saved_commit) { /* we already have a commit by this authority */

      /* We are in reveal phase: check if this new commitment includes
         the reveal value we were waiting for. */
      if (sr_state->phase == SR_PHASE_REVEAL && !saved_commit->reveal && commit->reveal) {
        log_warn(LD_GENERAL, "[SR] \t \t Ah, learned reveal value %s for commitment %s", commit->reveal, commit->commitment);
        /* XXX bad idea to change saved commit like this? */
        saved_commit->reveal = tor_strdup(commit->reveal);
        return;
      }

      log_warn(LD_GENERAL, "[SR] \t \t We already have this commitment by auth %s. Ignoring.",
               commit->auth_fingerprint);
      return;
    }
  }

  /* XXX we also need to make sure we don't use this commit value
     during _this_ voting session. */


  /* XXX check retval to see if there is already one with the same digest */
  digestmap_set(sr_state->commitments_tmp, (char *) commit->auth_digest, commit);

  log_warn(LD_GENERAL, "[SR] \t \t Found authoritative commit from %s (%s)",
           commit->auth_fingerprint, commit->commitment);
}

static int
commit_is_conflicting(const sr_commit_t *commit)
{
  sr_commit_t *saved_commit = get_commit_from_same_auth(commit);

  if (saved_commit) {

    if (strcmp(commit->commitment, saved_commit->commitment)) {
      return 1;
    }

  }

  return 0;
}

  return vote_str;
}

/* Prepare the shared random state we are going to be using for the upcoming
 * voting period at <b>valid_after</b>. This function should be called once at
 * the beginning of each new voting period. */
void
sr_prepare_state_for_new_voting_period(time_t valid_after)
{
  /* Init function should have been called long before this. */
  tor_assert(sr_state);

  /* Update the old state with information about this new round */
  update_state(valid_after);
}
