/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

char *
shared_random_compute_consensus(smartlist_t *votes,
                                int n_voters,
                                crypto_pk_t *identity_key,
                                crypto_pk_t *signing_key,
                                const char *legacy_id_key_digest,
                                crypto_pk_t *legacy_signing_key)
{
  smartlist_t *chunks;
  int n_votes = smartlist_len(votes);

  tor_assert(n_voters >= smartlist_len(votes));
  tor_assert(n_voters > 0);

  return "This is a test";
}
