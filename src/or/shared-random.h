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
#define SR_COMMIT_SIG_BODY_LEN (DIGEST256_LEN + 8)
/* Size of a decoded commit value in a vote or state. It consist of
   the signature body and the signature. This is 104 bytes. */
#define SR_COMMIT_LEN (SR_COMMIT_SIG_BODY_LEN + ED25519_SIG_LEN)
/* Size of a decoded reveal value from a vote or state. It's a 64 bit
 * timestamp and the random number. This adds up to 40 bytes. */
#define SR_REVEAL_LEN (8 + SR_RANDOM_NUMBER_LEN)
/* Size of SRV HMAC message length. The construction is has follow:
 *  "shared-random" | INT_8(reveal_num) | INT_8(version) | PREV_SRV */
#define SR_SRV_HMAC_MSG_LEN \
  (SR_SRV_TOKEN_LEN + 1 + 1 + DIGEST256_LEN)

/* Length of base64 encoded commit NOT including the NULL terminated byte.
 * Formula is taken from base64_encode_size. This adds up to 140 bytes. */
#define SR_COMMIT_BASE64_LEN \
  (((SR_COMMIT_LEN - 1) / 3) * 4 + 4)
/* Length of base64 encoded reveal NOT including the NULL terminated byte.
 * Formula is taken from base64_encode_size. This adds up to 56 bytes. */
#define SR_REVEAL_BASE64_LEN \
  (((SR_REVEAL_LEN - 1) / 3) * 4 + 4)

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

/* API */

int sr_init(int save_to_disk);
void sr_save_and_cleanup(void);

char *sr_get_commit_string_for_vote(void);
void sr_prepare_new_voting_period(time_t valid_after);

void sr_decide_post_voting(void);

void sr_commit_free(sr_commit_t *commit);
int sr_verify_commit_sig(const sr_commit_t *commit);

void sr_handle_received_commitment(const char *commit_pubkey,
                                   const char *hash_alg,
                                   const char *commitment,
                                   const char *reveal,
                                   const ed25519_public_key_t *voter_key);

sr_commit_t *sr_parse_commitment_line(smartlist_t *args);

sr_srv_status_t sr_get_srv_status_from_str(const char *name);
const char *sr_get_srv_status_str(sr_srv_status_t status);

void sr_compute_srv(void);
char *sr_get_consensus_srv_string(void);

sr_commit_t *sr_generate_our_commitment(time_t timestamp);

#ifdef SHARED_RANDOM_PRIVATE

/* Encode */
STATIC int reveal_encode(sr_commit_t *commit, char *dst, size_t len);
STATIC int commit_encode(sr_commit_t *commit, char *dst, size_t len);
/* Decode. */
STATIC int commit_decode(const char *encoded, sr_commit_t *commit);
STATIC int reveal_decode(const char *encoded, sr_commit_t *commit);

STATIC int verify_received_commit(const sr_commit_t *commit);

#endif /* SHARED_RANDOM_PRIVATE */

#endif /* TOR_SHARED_RANDOM_H */
