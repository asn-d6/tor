/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared-random.c
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 **/

#define SHARED_RANDOM_STATE_PRIVATE

#include "shared-random.h"
#include "config.h"
#include "confparse.h"
#include "shared-random-state.h"

/* Default filename of the shared random state on disk. */
static const char *default_fname = "sr-state";

/* String representation of a protocol phase. */
static const char *phase_str[] = { "unknown", "commit", "reveal" };

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

/* These next two are duplicates or near-duplicates from config.c */
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
/* XXX: Only for testing faster! To fix. */
//#define SHARED_RANDOM_N_ROUNDS 12
#define SHARED_RANDOM_N_ROUNDS 3

static int
disk_state_validate_cb(void *old_state, void *state, void *default_state,
                       int from_setconf, char **msg);

/* Array of variables that are saved to disk as a persistent state. */
static config_var_t state_vars[] = {
  V(Version,                    INT, "1"),
  V(ValidUntil,                 ISOTIME, NULL),
  V(ProtocolPhase,              STRING, NULL),

  VAR("Commitment",             LINELIST_S, Commitments, NULL),
  V(Commitments,                LINELIST_V, NULL),
  VAR("Conflict",               LINELIST_S, Conflicts, NULL),
  V(Conflicts,                  LINELIST_V, NULL),

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

/* Return the current protocol phase on a testing network. */
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

/* Add a <b>conflict</b> object to the given <b>state</b>. */
static void
conflict_add_to_state(sr_conflict_commit_t *conflict, sr_state_t *state)
{
  sr_conflict_commit_t *saved;

  tor_assert(conflict);
  tor_assert(state);

  /* Replace current value if any and free the old one if any. */
  saved = digest256map_set(state->conflicts,
                           conflict->commit1->auth_identity.pubkey,
                           conflict);
  sr_conflict_commit_free(saved);
  log_warn(LD_DIR, "[SR] Authority %s has just triggered a conflict. "
           "It will be ignored for the rest of the protocol run.",
           conflict->commit1->auth_fingerprint);
}

/* Add the given <b>commit</b> to <b>state</b>. It MUST be a valid commit
 * and there shouldn't be a commit from the same authority in the state
 * already else conflict verification hasn't been done prior. */
static void
commit_add_to_state(sr_commit_t *commit, sr_state_t *state)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(state);

  saved_commit = digest256map_set(state->commitments,
                                  commit->auth_identity.pubkey, commit);
  tor_assert(saved_commit == NULL);
}

/* Helper: deallocate a commit object. (Used with digest256map_free(), which
 * requires a function pointer whose argument is void *). */
static void
commit_free_(void *p)
{
  sr_commit_free(p);
}

/* Helper: deallocate a conflict commit object. (Used with
 * digest256map_free(), which requires a function pointer whose argument is
 * void *). */
static void
conflict_commit_free_(void *p)
{
  sr_conflict_commit_free(p);
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
  if (state == NULL) {
    return;
  }
  config_free(&state_format, state);
  tor_free(state);
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

/* Return -1 if the disk state is invalid that is something in there that we
 * can't or shouldn't use. Return 0 if everything checks out. */
static int
disk_state_validate(sr_disk_state_t *state)
{
  time_t now;

  tor_assert(state);

  now = time(NULL);

  /* Do we support the protocol version in the state?. */
  if (state->Version > SR_PROTO_VERSION) {
    goto invalid;
  }
  /* If the valid until time is before now, we shouldn't use that state. */
  if (state->ValidUntil < now) {
    goto invalid;
  }
  /* If our state is in a different protocol phase that we are suppose to
   * be, we consider it invalid. */
  {
    sr_phase_t current_phase = get_sr_protocol_phase(now);
    if (get_phase_from_str(state->ProtocolPhase) != current_phase) {
      goto invalid;
    }
  }

  return 0;
 invalid:
  return -1;
}

static int
disk_state_validate_cb(void *old_state, void *state, void *default_state,
                       int from_setconf, char **msg)
{
  /* We don't use these; only options do. */
  (void) from_setconf;
  (void) default_state;
  (void) old_state;

  /* XXX: Validate phase, version, time, commitments, conflicts and SRV
   * format. This is called by config_dump which is just before we are about
   * to write it to disk so we should verify the format and not parse
   * everything again. At that point, our global memory state has been
   * copied to the disk state so it's fair to assume it's trustable. So,
   * only verify the format of the strings. */
  (void) state;
  (void) msg;
  return 0;
}

/* Parse the Commitment line(s) in the disk state and translate them to the
 * the memory state. Return 0 on success else -1 on error. */
static int
disk_state_parse_commits(sr_state_t *state, sr_disk_state_t *disk_state)
{
  config_line_t *line;
  smartlist_t *args = NULL;

  tor_assert(state);
  tor_assert(disk_state);

  for (line = disk_state->Commitments; line; line = line->next) {
    sr_commit_t *commit = NULL;

    /* Extra safety. */
    if (strcasecmp(line->key, dstate_commit_key) ||
        line->value == NULL) {
      /* Ignore any lines that are not commits. */
      continue;
    }
    args = smartlist_new();
    smartlist_split_string(args, line->value, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args) < 4) {
      log_warn(LD_DIR, "Too few arguments to Commitment. Line: \"%s\"",
               line->value);
      goto error;
    }
    commit = sr_parse_commitment_line(args);
    if (commit == NULL) {
      goto error;
    }
    /* Commit was decoded correctly, let's verify it. */
    if (!sr_verify_commit(commit)) {
      goto error;
    }
    /* Add commit to our state pointer. */
    commit_add_to_state(commit, state);

    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
  }

  return 0;
error:
  smartlist_free(args);
  return -1;
}

/* Parse Conflict line(s) in the disk state and translate them to the the
 * memory state. Return 0 on success else -1 on error. */
static int
disk_state_parse_conflicts(sr_state_t *state, sr_disk_state_t *disk_state)
{
  config_line_t *line;
  smartlist_t *args = NULL;

  tor_assert(state);
  tor_assert(disk_state);

  for (line = disk_state->Conflicts; line; line = line->next) {
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
      log_warn(LD_DIR, "Too few arguments to Conflict. Line: \"%s\"",
               line->value);
      goto error;
    }
    conflict = sr_parse_conflict_line(args);
    if (conflict == NULL) {
      goto error;
    }
    /* Conflict was decoded correctly, let's verify it. */
    if (!sr_verify_conflict(conflict)) {
      goto error;
    }
    /* Add conflict to our state pointer. */
    conflict_add_to_state(conflict, state);

    SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
    smartlist_free(args);
  }

  return 0;
error:
  smartlist_free(args);
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
    log_warn(LD_DIR, "Too few arguments to shared random value. "
             "Line: \"%s\"", value);
    goto error;
  }

  /* First argument is the status. */
  status = sr_get_srv_status_from_str(smartlist_get(args, 0));
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

/* From a valid conflict object and an allocated config line, set the line's
 * value to the state string representation of a conflict. */
static void
disk_state_put_conflict_line(sr_conflict_commit_t *conflict,
                             config_line_t *line)
{
  tor_assert(conflict);
  tor_assert(line);

  /* We can construct a reveal string if the random number exists meaning
   * it's ours or we got it during the reveal phase. */
  tor_asprintf(&line->value, "%s %s %s",
               conflict->commit1->auth_fingerprint,
               conflict->commit1->encoded_commit,
               conflict->commit2->encoded_commit);
}

/* From a valid commit object and an allocated config line, set the line's
 * value to the state string representation of a commit. */
static void
disk_state_put_commit_line(sr_commit_t *commit, config_line_t *line)
{
  char *reveal_str = NULL;

  tor_assert(commit);
  tor_assert(line);

  if (!tor_mem_is_zero(commit->encoded_reveal,
                       sizeof(commit->encoded_reveal))) {
    /* Add extra whitespace so we can format the line correctly. */
    tor_asprintf(&reveal_str, " %s", commit->encoded_reveal);
  }
  tor_asprintf(&line->value, "%s %s %s %s%s",
               crypto_digest_algorithm_get_name(commit->alg),
               commit->auth_fingerprint,
               commit->has_majority ? "1" : "0",
               commit->encoded_commit,
               reveal_str != NULL ? reveal_str : "");
  tor_free(reveal_str);
}

/* From a valid srv object and an allocated config line, set the line's
 * value to the state string representation of a shared random value. */
static void
disk_state_put_srv_line(sr_srv_t *srv, config_line_t *line)
{
  char encoded[HEX_DIGEST256_LEN + 1];

  tor_assert(line);

  /* No SRV value thus don't add the line. This is possible since we might
   * not have a current or previous SRV value in our state. */
  if (srv == NULL) {
    return;
  }
  base16_encode(encoded, sizeof(encoded), (const char *) srv->value,
                sizeof(srv->value));
  tor_asprintf(&line->value, "%s %s", sr_get_srv_status_str(srv->status),
               encoded);
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
  if (sr_state->previous_srv != NULL) {
    line = sr_disk_state->SharedRandPreviousValue =
      tor_malloc_zero(sizeof(*line));
    line->key = tor_strdup(dstate_prev_srv_key);
    disk_state_put_srv_line(sr_state->previous_srv, line);
  }
  if (sr_state->current_srv != NULL) {
    line = sr_disk_state->SharedRandCurrentValue =
      tor_malloc_zero(sizeof(*line));
    line->key = tor_strdup(dstate_cur_srv_key);
    disk_state_put_srv_line(sr_state->current_srv, line);
  }

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
      log_warn(LD_DIR, "%s", errmsg);
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
    ret = -EINVAL;
    goto error;
  }
  state_set(parsed_state);
  disk_state_set(disk_state);
  log_notice(LD_DIR, "[SR] State loaded from \"%s\"", fname);
  return 0;
error:
  disk_state_free(disk_state);
  return ret;
}

/* Save the disk state to disk but before that update it from the current
 * state so we always have the latest. Return 0 on success else -1. */
static int
disk_state_save_to_disk(void)
{
  int ret;
  char *state, *content = NULL, *fname = NULL;
  char tbuf[ISO_TIME_LEN + 1];
  time_t now = time(NULL);

  /* If we didn't have the opportunity to setup an internal disk state,
   * don't bother saving something to disk. */
  if (sr_disk_state == NULL) {
    ret = 0;
    goto done;
  }

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
  log_info(LD_DIR, "Saved SR state to \"%s\"", fname);

done:
  tor_free(fname);
  tor_free(content);
  return ret;
}

/* Return 1 iff we are just booting off. We use the number of protocol runs
 * we've seen so far to know that which is 0 at first. */
static int
is_booting_up(void)
{
  return !sr_state->n_protocol_runs;
}

/** This is the first round of the new protocol run starting at
 *  <b>valid_after</b>. Do the necessary housekeeping. */
static void
new_protocol_run(time_t valid_after)
{
  sr_commit_t *our_commitment = NULL;

  /* Only compute the srv at the end of the reveal phase. */
  if (sr_state->phase == SR_PHASE_REVEAL && !is_booting_up()) {
    /* We are about to compute a new shared random value that will be set in
     * our state as the current value so swap the current to the previous
     * value right now. */
    tor_free(sr_state->previous_srv);
    sr_state->previous_srv = sr_state->current_srv;
    sr_state->current_srv = NULL;
    /* Compute the shared randomness value of the day. */
    sr_compute_srv();
  }

  /* Keep counters in track */
  sr_state->n_reveal_rounds = 0;
  sr_state->n_commit_rounds = 0;
  sr_state->n_protocol_runs++;

  /* Do some logging */
  log_warn(LD_DIR, "[SR] =========================");
  log_warn(LD_DIR, "[SR] Protocol run #%" PRIu64 " starting!",
           sr_state->n_protocol_runs);

  /* We are in a new protocol run so cleanup commitments and conflicts. */
  DIGEST256MAP_FOREACH_MODIFY(sr_state->commitments, key, sr_commit_t *, c) {
    sr_commit_free(c);
    MAP_DEL_CURRENT(key);
  } DIGEST256MAP_FOREACH_END;
  DIGEST256MAP_FOREACH_MODIFY(sr_state->conflicts, key,
                              sr_conflict_commit_t *, c) {
    sr_conflict_commit_free(c);
    MAP_DEL_CURRENT(key);
  } DIGEST256MAP_FOREACH_END;

  /* Generate fresh commitments for this protocol run */
  our_commitment = sr_generate_our_commitment(valid_after);
  if (our_commitment) {
    /* Add our commitment to our state. In case we are unable to create one
     * (highly unlikely), we won't vote for this protocol run since our
     * commitment won't be in our state. */
    commit_add_to_state(our_commitment, sr_state);
  }
}

/* Transition from the commit phase to the reveal phase by sanitizing our
 * state and making sure it's coherent to get in the reveal phase. */
static void
new_reveal_phase(void)
{
  tor_assert(sr_state->phase != SR_PHASE_REVEAL);
  tor_assert(sr_state->n_reveal_rounds == 0);

  log_warn(LD_DIR, "[SR] Transition to reveal phase!");

  /* Remove commitments that do NOT have majority. */
  DIGEST256MAP_FOREACH_MODIFY(sr_state->commitments, key, sr_commit_t *,
                              commit) {
    sr_conflict_commit_t *conflict;

    if (!commit->has_majority) {
      log_warn(LD_DIR, "[SR] Commit from %s has NO majority. Cleaning",
               commit->auth_fingerprint);
      sr_commit_free(commit);
      MAP_DEL_CURRENT(key);
      /* Commit is out, we are done here. */
      continue;
    }
    /* Safety net, we shouldn't have a commit from an authority that also
     * has a conflict for the same authority. If so, this is a BUG so log it
     * and clean it. */
    conflict = sr_state_get_conflict(&commit->auth_identity);
    if (conflict != NULL) {
      log_warn(LD_DIR, "[SR] BUG: Commit found for authority %s "
                       "but we have a conflict for this authority.",
               commit->auth_fingerprint);
      sr_commit_free(commit);
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

/* Return the phase we are currently in according to our state. */
sr_phase_t
sr_state_get_phase(void)
{
  return sr_state->phase;
}

/* Return the previous SRV value from our state. Value CAN be NULL. */
sr_srv_t *
sr_state_get_previous_srv(void)
{
  return sr_state->previous_srv;
}

/* Set the current SRV value from our state. Value CAN be NULL. */
void
sr_state_set_previous_srv(sr_srv_t *srv)
{
  tor_assert(srv);
  sr_state->previous_srv = srv;
}

/* Return the current SRV value from our state. Value CAN be NULL. */
sr_srv_t *
sr_state_get_current_srv(void)
{
  return sr_state->current_srv;
}

/* Set the current SRV value from our state. Value CAN be NULL. */
void
sr_state_set_current_srv(sr_srv_t *srv)
{
  tor_assert(srv);
  sr_state->current_srv = srv;
}

/* Return a pointer to the commits map from our state. */
digest256map_t *
sr_state_get_commits(void)
{
  return sr_state->commitments;
}

/* Return a pointer to the conflict map from our state. */
digest256map_t *
sr_state_get_conflicts(void)
{
  return sr_state->conflicts;
}

/* Update the current SR state as needed for the upcoming voting round at
 * <b>valid_after</b>. Don't call this function twice in the same voting
 * period. */
void
sr_state_update(time_t valid_after)
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
      new_protocol_run(valid_after);
      break;
    case SR_PHASE_REVEAL:
      /* We were in the commit phase thus now in reveal. */
      new_reveal_phase();
      break;
    }
    /* Set the new phase for this round */
    sr_state->phase = new_phase;
  } else if (is_booting_up()) {
    /* We are just booting up this means there is no chance we are in a
     * phase transition thus consider this a new protocol run. */
    new_protocol_run(valid_after);
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
    log_warn(LD_DIR, "[SR] State prepared for new voting period (%s). "
             "Current phase is %s (%d/%d).",
             tbuf, get_phase_str(sr_state->phase),
             sr_state->n_commit_rounds, sr_state->n_reveal_rounds);
  }
}

/* Return commit object from the given authority digest <b>identity</b>.
 * Return NULL if not found. */
sr_commit_t *
sr_state_get_commit(const ed25519_public_key_t *identity)
{
  tor_assert(identity);
  return digest256map_get(sr_state->commitments, identity->pubkey);
}

/* Return conflict object from the given authority digest <b>identity</b>.
 * Return NULL if not found. */
sr_conflict_commit_t *
sr_state_get_conflict(const ed25519_public_key_t *identity)
{
  tor_assert(identity);
  return digest256map_get(sr_state->conflicts, identity->pubkey);
}

/* Add a conflict to the state using the different commits <b>c1</b> and
 * <b>c2</b>. If a conflict already exists, update it with those values. */
void
sr_state_add_conflict(sr_conflict_commit_t *conflict)
{
  sr_conflict_commit_t *saved;

  tor_assert(conflict);
  tor_assert(conflict->commit1);
  tor_assert(conflict->commit2);

  /* It's possible to add a conflict for an authority that already has a
   * conflict in our state so we update the entry with the latest one. */
  saved = digest256map_set(sr_state->conflicts,
                           conflict->commit1->auth_identity.pubkey,
                           conflict);
  if (saved != conflict) {
    sr_conflict_commit_free(saved);
  }
}

/* Add <b>commit</b> to the permanent state. Make sure there are no
 * conflicts. The given commit is duped so the caller should free the memory
 * if needed upon return. */
void
sr_state_add_commit(sr_commit_t *commit)
{
  sr_commit_t *saved_commit = NULL;

  tor_assert(commit);

  saved_commit = sr_state_get_commit(&commit->auth_identity);
  if (saved_commit != NULL) {
    /* MUST be same pointer else there is a code flow issue. */
    tor_assert(saved_commit == commit);
  }
  /* Add the commit to our global state. */
  commit_add_to_state(commit, sr_state);

  log_warn(LD_DIR, "[SR] \t Commit from %s has been added to our state. "
                   "It's %sauthoritative and has %smajority",
           commit->auth_fingerprint,
           commit->is_authoritative ? "" : "NOT ",
           commit->has_majority ? "" : "NO ");
}

/* Remove a commit entry identified by <b>key</b> from our state. */
void
sr_state_remove_commit(const ed25519_public_key_t *key)
{
  tor_assert(key);
  digest256map_remove(sr_state->commitments, key->pubkey);
}

/* Cleanup and free our disk and memory state. */
void
sr_state_free(void)
{
  state_free(sr_state);
  disk_state_free(sr_disk_state);
  /* Nullify our global state. */
  sr_state = NULL;
  sr_disk_state = NULL;
}

/* Save our current state in memory to disk. */
void
sr_state_save(void)
{
  disk_state_save_to_disk();
}

/* Initialize the disk and memory state. Return 0 on success else a negative
 * value on error. */
int
sr_state_init(int save_to_disk)
{
  int ret;

  /* We shouldn't have those assigned. */
  tor_assert(sr_disk_state == NULL);
  tor_assert(sr_state == NULL);

  /* First, we have to try to load the state from disk. */
  ret = disk_state_load_from_disk();
  if (ret < 0) {
    switch (-ret) {
    case EINVAL:
      /* We have a state on disk but it contains something we couldn't parse
       * or an invalid entry in the state file. Let's remove it since it's
       * obviously unusable and replace it by an new fresh state below. */
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
          goto error;
        }
        break;
      }
    default:
      /* Big problem. Not possible. */
      tor_assert(0);
    }
  }
  return 0;
error:
  return -1;
}
