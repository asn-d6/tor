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
/* Invariant token in the SRV calculation. */
#define SR_SRV_TOKEN "shared-random"
/* Don't count the NULL terminated byte even though the TOKEN has it. */
#define SR_SRV_TOKEN_LEN (sizeof(SR_SRV_TOKEN) - 1)
/* Minimum number of reveal values needed to compute a SRV value. */
#define SR_SRV_MIN_REVEAL 3

/* Length of the random number (in bytes). */
#define SR_RANDOM_NUMBER_LEN 32
/* The signature includes the sha256 hash of the reveal + a 64bit timestamp */
#define SR_COMMIT_SIG_BODY_LEN (DIGEST256_LEN + sizeof(uint64_t))
/* Size of a decoded commit value in a vote or state. It consist of
   the signature body and the signature */
#define SR_COMMIT_LEN (SR_COMMIT_SIG_BODY_LEN + ED25519_SIG_LEN)
/* Size of a decoded reveal value from a vote or state. It's a 64 bit
 * timestamp and the random number. */
#define SR_REVEAL_LEN \
  (sizeof(uint64_t) + SR_RANDOM_NUMBER_LEN)
/* Size of SRV HMAC message length. The construction is has follow:
 *  "shared-random" | INT_8(reveal_num) | INT_8(version) | PREV_SRV */
#define SR_SRV_HMAC_MSG_LEN \
  (SR_SRV_TOKEN_LEN + sizeof(uint8_t) + sizeof(uint8_t) + DIGEST256_LEN)

/* Length of base64 encoded commit. Formula is taken from base64_encode.
 * Currently, this adds up to 96 bytes. */
#define SR_COMMIT_BASE64_LEN \
  (((SR_COMMIT_LEN - 1) / 3) * 4 + 4 + 1)
/* Length of base64 encoded reveal. Formula is taken from base64_encode.
 * Currently, this adds up to 56 bytes. */
#define SR_REVEAL_BASE64_LEN \
  (((SR_REVEAL_LEN - 1) / 3) * 4 + 4 + 1)

/* Protocol phase. */
typedef enum {
  /* We are commitment phase */
  SR_PHASE_COMMIT  = 1,
  /* We are reveal phase */
  SR_PHASE_REVEAL  = 2,
} sr_phase_t;

/* Shared random value status. */
typedef enum {
  SR_SRV_STATUS_FRESH =    0,
  SR_SRV_STATUS_NONFRESH = 1,
} sr_srv_status_t;

/* A shared random value object that contains its status and value. */
typedef struct sr_srv_t {
  /* Is this value a fresh value meaning it was succesfully computed or
   * non-fresh which means we didn't have enough reveal values thus we used
   * the fallback computation method. */
  sr_srv_status_t status;
  /* The actual value. This is the stored result of HMAC-SHA256. */
  uint8_t value[DIGEST256_LEN];
} sr_srv_t;

/* A commitment value that can be ours or from other authority. */
typedef struct sr_commit_t {
  /* Hashing algorithm used for the value. Depends on the version of the
   * protocol located in the state. */
  digest_algorithm_t alg;
  /* Is this commit has reached majority? */
  unsigned int has_majority:1;
  /* Is this commit an authoritative commit that is a vote from a directory
   * authority received from that authority. */
  unsigned int is_authoritative:1;
  /* Signature of the commit that has been verified against the
   * identity and thus valid. */
  ed25519_signature_t signature;

  /** Commitment owner info */

  /* Authority ed25519 identity from which this commitment is. */
  ed25519_public_key_t auth_identity;
  /* Authority ed25519 identity key fingerprint base64 format. We keep it
   * for logging purposes instead of encoding each time. */
  char auth_fingerprint[ED25519_BASE64_LEN + 1];

  /** Commitment information */

  /* Signature of the commit that has been verified against the
   * identity and thus valid. */
  ed25519_signature_t commit_signature;
  /* Timestamp of reveal. Correspond to TIMESTAMP. */
  time_t reveal_ts;
  /* H(REVEAL) as found in COMMIT message. */
  char hashed_reveal[DIGEST256_LEN];
  /* Base64 encoded COMMIT. We use this to put it in our vote. */
  char encoded_commit[SR_COMMIT_BASE64_LEN + 1];

  /** Reveal information */

  /* 256 bit random number. Correspond to RN. */
  uint8_t random_number[SR_RANDOM_NUMBER_LEN];
  /* Timestamp of commit. Correspond to TIMESTAMP. */
  time_t commit_ts;
  /* This is the whole reveal message. We use it during verification */
  char encoded_reveal[SR_REVEAL_BASE64_LEN + 1];
} sr_commit_t;

/* Represent a commit conflict. See section [COMMITCONFLICT] in proposal
 * 250. A conflict is valid only for a full protocol run. */
typedef struct sr_conflict_commit_t {
  /* Authority ed25519 identity of the conflict commit. */
  ed25519_public_key_t auth_identity;
  /* First commit has been seen before the second one. */
  sr_commit_t *commit1, *commit2;
} sr_conflict_commit_t;

/* State of the protocol. It's also saved on disk in fname. This data
 * structure MUST be synchronized at all time with the one on disk. */
typedef struct sr_state_t {
  /* Number of runs completed. */
  uint64_t n_protocol_runs;

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
  sr_srv_t *previous_srv;
  sr_srv_t *current_srv;

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

void sr_decide_state_post_voting(smartlist_t *votes);

sr_commit_t * sr_handle_received_commitment(const char *commit_pubkey,
                                            const char *hash_alg,
                                            const char *commitment,
                                            const char *reveal);

#ifdef SHARED_RANDOM_PRIVATE

STATIC int reveal_encode(sr_commit_t *commit, char *dst, size_t len);
STATIC int commit_encode(sr_commit_t *commit, char *dst, size_t len);

STATIC sr_phase_t get_sr_protocol_phase(time_t valid_after);

STATIC sr_commit_t *generate_sr_commitment(time_t timestamp);

STATIC int parse_encoded_commit(const char *encoded, sr_commit_t *commit);
STATIC int parse_encoded_reveal(const char *encoded, sr_commit_t *commit);

STATIC int verify_commit_and_reveal(const sr_commit_t *commit);

#endif

#endif /* TOR_SHARED_RANDOM_H */
