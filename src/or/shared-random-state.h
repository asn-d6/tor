/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_SHARED_RANDOM_STATE_H
#define TOR_SHARED_RANDOM_STATE_H

#include "shared-random.h"

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
  /* List of commit conflicts seen by this authority. */
  digest256map_t *conflicts;

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
  /* Which protocol phase are we in? */
  char *ProtocolPhase;
  /* All commitments seen that are valid. */
  config_line_t *Commitments;
  /* All conflict seen. */
  config_line_t *Conflicts;
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

digest256map_t *sr_state_get_commits(void);
digest256map_t *sr_state_get_conflicts(void);

sr_commit_t *sr_state_get_commit(const ed25519_public_key_t *identity);
sr_conflict_commit_t *sr_state_get_conflict(
                                 const ed25519_public_key_t *identity);
void sr_state_add_conflict(sr_conflict_commit_t *conflict);
void sr_state_add_commit(sr_commit_t *commit);
void sr_state_remove_commit(const ed25519_public_key_t *key);

void sr_state_update(time_t valid_after);
int sr_state_init(int save_to_disk);
void sr_state_save(void);
void sr_state_free(void);

#ifdef SHARED_RANDOM_STATE_PRIVATE

STATIC sr_phase_t get_sr_protocol_phase(time_t valid_after);

#endif /* SHARED_RANDOM_STATE_PRIVATE */

#endif /* TOR_SHARED_RANDOM_STATE_H */
