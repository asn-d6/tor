/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

typedef struct shared_random_doc_t {
  time_t valid_until;

  /** Digests of this document, as signed. */
  digests_t digests;
} shared_random_doc_t;

int shared_random_compute_sr_doc(consensus_creation_helper_t *consensus_info);
