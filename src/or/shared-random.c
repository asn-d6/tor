/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

int
get_current_phase(time_t now)
{
if (SHARED_RANDOM_START_TIME +
    SHARED_RANDOM_TIME_INTERVAL * SHARED_RANDOM_N_ROUNDS <= now) {
  ; /* commit */
 } else {
  ; /* reveal */
}

char *
compute_shared_random_consensus(smartlist_t *votes,
                                int n_voters,
                                crypto_pk_t *identity_key,
                                crypto_pk_t *signing_key,
                                const char *legacy_id_key_digest,
                                crypto_pk_t *legacy_signing_key) {
  int n_votes = smartlist_len(votes);
  smartlist_t *chunks = smartlist_new();
  char *output = NULL;

  tor_assert(n_voters >= smartlist_len(votes));
  tor_assert(n_voters > 0);

  smartlist_add_asprintf(chunks, "shared-random-version 1 shared-random");
  //  smartlist_add_asprintfcreated, "created %s");
  smartlist_add_asprintf(chunks, "valid-until %s %s", "2420-11-09", "00:00:00");
  smartlist_add_asprintf(chunks, "protocol-phase %s", "night");

  /*
    "shared-rand-commitment" SP algname SP identity SP commitment-value
    "shared-rand-previous-value" SP status SP value NL
    "shared-rand-current-value" SP status SP value NL
  */

  output = smartlist_join_strings(chunks, "\n", 0, NULL);

  return output;
}
