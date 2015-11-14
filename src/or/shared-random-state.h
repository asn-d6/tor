/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_SHARED_RANDOM_STATE_H
#define TOR_SHARED_RANDOM_STATE_H

#include "shared-random.h"

/* Action that can be performed on the state for any objects. */
typedef enum {
  SR_STATE_ACTION_GET   = 1,
  SR_STATE_ACTION_PUT   = 2,
  SR_STATE_ACTION_DEL   = 3,
  SR_STATE_ACTION_SAVE  = 4,
} sr_state_action_t;

/* Object in the state that can be queried through the state API. */
typedef enum {
  /* Will return a single commit using an authority master ed25519 key. */
  SR_STATE_OBJ_COMMIT,
  /* Will return a single commit using an authority RSA key. */
  SR_STATE_OBJ_COMMIT_RSA,
  /* Returns the entire list of commits from the state. */
  SR_STATE_OBJ_COMMITS,
  /* Return the current SRV object pointer. */
  SR_STATE_OBJ_CURSRV,
  /* Return the previous SRV object pointer. */
  SR_STATE_OBJ_PREVSRV,
  /* Return the phase. */
  SR_STATE_OBJ_PHASE,
} sr_state_object_t;

/* State of the protocol. It's also saved on disk in fname. This data
 * structure MUST be synchronized at all time with the one on disk. */
typedef struct sr_state_t {
  /* Filename of the state file on disk. */
  char *fname;
  /* Version of the protocol. */
  uint8_t version;
  /* Until when this state is valid? */
  time_t valid_until;
  /* Protocol phase. */
  sr_phase_t phase;

  /* Number of runs completed. */
  uint64_t n_protocol_runs;
  /* The number of commitment rounds we've performed in this protocol run. */
  unsigned int n_commit_rounds;
  /* The number of reveal rounds we've performed in this protocol run. */
  unsigned int n_reveal_rounds;

  /* A map of all the receive commitments for the protocol run. This is
   * indexed by authority identity digest. */
  digest256map_t *commitments;

  /* Current and previous shared random value. See section [SRCALC] in
   * proposal 250 for details on how this is constructed. */
  sr_srv_t *previous_srv;
  sr_srv_t *current_srv;
} sr_state_t;

/* Persistent state of the protocol, as saved to disk. */
typedef struct sr_disk_state_t {
  uint32_t magic_;
  /* Version of the protocol. */
  int Version;
  /* State valid until? */
  time_t ValidUntil;
  /* All commitments seen that are valid. */
  config_line_t *Commitments;
  /* Previous and current shared random value. */
  config_line_t *SharedRandPreviousValue;
  config_line_t *SharedRandCurrentValue;
  /* Extra Lines for configuration we might not know. */
  config_line_t *ExtraLines;
} sr_disk_state_t;

/* API */

sr_phase_t sr_state_get_phase(void);

sr_srv_t *sr_state_get_previous_srv(void);
sr_srv_t *sr_state_get_current_srv(void);
void sr_state_set_previous_srv(sr_srv_t *srv);
void sr_state_set_current_srv(sr_srv_t *srv);
void sr_state_rotate_srv(void);

digest256map_t *sr_state_get_commits(void);
sr_commit_t *sr_state_get_commit_by_rsa(const char* rsa_fpr);
sr_commit_t *sr_state_get_commit(const ed25519_public_key_t *identity);
void sr_state_add_commit(sr_commit_t *commit);
void sr_state_remove_commit(const ed25519_public_key_t *key);
void sr_state_set_commit_reveal(sr_commit_t *commit,
                                const char *encoded_reveal);

void sr_state_update(time_t valid_after);
int sr_state_init(int save_to_disk);
void sr_state_save(void);
void sr_state_free(void);

#ifdef SHARED_RANDOM_STATE_PRIVATE

STATIC sr_phase_t get_sr_protocol_phase(time_t valid_after);

STATIC time_t get_state_valid_until_time(time_t now);

STATIC sr_commit_t *state_query_get_commit_by_rsa(const char *rsa_fpr);

#endif /* SHARED_RANDOM_STATE_PRIVATE */

#ifdef TOR_UNIT_TESTS
STATIC void set_sr_phase(sr_phase_t phase);
#endif


#endif /* TOR_SHARED_RANDOM_STATE_H */
