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
  uint8_t previous_srv[DIGEST256_LEN];
  uint8_t current_srv[DIGEST256_LEN];

  /* List of commit conflicts seen by this authority. */
  digest256map_t *conflicts;
} sr_state_t;

#endif /* TOR_SHARED_RANDOM_H */
