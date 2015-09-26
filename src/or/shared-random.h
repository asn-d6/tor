/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_SHARED_RANDOM_H
#define TOR_SHARED_RANDOM_H

/*
 * This file contains ABI/API of the shared random protocol defined in
 * proposal #250. Every public functions and data structure are namespaced
 * with "sr_" which stands for shared random.
 */

#include "or.h"

/* Protocol version */
#define SR_PROTO_VERSION  1
/* Current digest algorithm. */
#define SR_DIGEST_ALG DIGEST_SHA256

/* Length of the random number (in bytes). */
#define SR_RANDOM_NUMBER_LEN 32
/* Size of a decoded commit value in a vote or state. It consist of a 64 bit
 * timestamp, SHA256 hash digest and signature. */
#define SR_COMMIT_LEN \
  (sizeof(uint64_t) + DIGEST256_LEN + ED25519_SIG_LEN)
/* Size of a decoded reveal value from a vote or state. It's a 64 bit
 * timestamp and the random number. */
#define SR_REVEAL_LEN \
  (sizeof(uint64_t) + SR_RANDOM_NUMBER_LEN)
/* Length of base64 encoded commit. Formula is taken from base64_encode.
 * Currently, this adds up to 96 bytes. */
#define SR_COMMIT_BASE64_LEN \
  (((SR_COMMIT_LEN - 1) / 3) * 4 + 4)
/* Length of base64 encoded reveal. Formula is taken from base64_encode.
 * Currently, this adds up to 56 bytes. */
#define SR_REVEAL_BASE64_LEN \
  (((SR_REVEAL_LEN - 1) / 3) * 4 + 4)

/* Protocol phase. */
typedef enum {
  /* We just started we still don't know what phase we are in. */
  SR_PHASE_UNKNOWN = 0,
  /* We are commitment phase */
  SR_PHASE_COMMIT = 1,
  /* We are reveal phase */
  SR_PHASE_REVEAL = 2,
} sr_phase_t;

/* Shared random value status. */
typedef enum {
  SR_SRV_STATUS_FRESH =    0,
  SR_SRV_STATUS_NONFRESH = 1,
} sr_srv_status_t;

/* A shared random value object that contains its status and value. */
typedef struct sr_srv_t {
  sr_srv_status_t status;
  uint8_t value[DIGEST256_LEN];
} sr_srv_t;

/* A commitment value that can be ours or from other authority. */
typedef struct sr_commit_t {
  /* Hashing algorithm used for the value. Depends on the version of the
   * protocol located in the state. */
  digest_algorithm_t alg;
  /* Authority ed25519 identity from which this commitment is. */
  uint8_t identity[ED25519_PUBKEY_LEN];
  /* Timestamp of when the commitment has been received */
  time_t received_ts;
  /* Timestamp of the commitment value. Correspond to TIMESTAMP. */
  time_t commit_ts;
  /* Hashed of the reveal value. Correspond to H(REVEAL). */
  char reveal_hash[DIGEST256_LEN];
  /* Signature of the commit that has been verified against the
   * identity and thus valid. */
  ed25519_signature_t signature;
  /* 256 bit random number. Correspond to RN. */
  uint8_t random_number[32];
  /* Is this commit has reached majority? */
  unsigned int has_majority:1;

  /* ************************************************************ */

  /* Fingerprint of authority this commitment belongs to */
  char *auth_fingerprint; /* XXX temp till we use ed25519 */
  uint8_t auth_digest[DIGEST_LEN];

  char *commitment; /* XXX temp till we use ed25519 */

  char *reveal; /* XXX temp till we use ed25519 */
} sr_commit_t;

/* Represent a commit conflict. See section [COMMITCONFLICT] in proposal
 * 250. A conflict is valid only for a full protocol run. */
typedef struct sr_conflict_commit_t {
  /* Authority ed25519 identity from which this commitment is. */
  uint8_t identity[ED25519_PUBKEY_LEN];
  /* First commit has been seen before the second one. */
  sr_commit_t *commit1, *commit2;
} sr_conflict_commit_t;

/* State of the protocol. It's also saved on disk in fname. This data
 * structure MUST be synchronized at all time with the one on disk. */
typedef struct sr_state_t {
  /* Filename of the state file on disk. */
  char *fname;
  /* Version of the protocol. */
  unsigned int version;
  /* Until when this state is valid? */
  time_t valid_until;
  /* Protocol phase. */
  sr_phase_t phase;

  /* A map of all the receive commitments for the protocol run. This is
   * indexed by authority identity digest. */
  digest256map_t *commitments;

  /* Current and previous shared random value. See section [SRCALC] in
   * proposal 250 for details on how this is constructed. */
  sr_srv_t previous_srv;
  sr_srv_t current_srv;

  /* List of commit conflicts seen by this authority. */
  digest256map_t *conflicts;

  /* The number of commitment rounds we've performed in this protocol run. */
  int n_commit_rounds;
  /* The number of reveal rounds we've performed in this protocol run. */
  int n_reveal_rounds;
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

int sr_init(int save_to_disk);
void sr_save_and_cleanup(void);

char *sr_get_string_for_vote(void);
void sr_prepare_state_for_new_voting_period(time_t valid_after);

#ifdef SHARED_RANDOM_PRIVATE

STATIC sr_phase_t get_sr_protocol_phase(time_t valid_after);

#endif

#endif /* TOR_SHARED_RANDOM_H */
