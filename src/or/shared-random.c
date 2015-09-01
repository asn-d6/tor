/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "shared-random.h"
#include "dirvote.h"

void
shared_random_doc_free(shared_random_doc_t *sr_doc)
{
  if (!sr_doc) {
    return;
  }

  tor_free(sr_doc);
}


static char *
compute_sr_doc_body(const consensus_creation_helper_t *consensus_info)
{
  smartlist_t *chunks = smartlist_new();
  char *output = NULL;

  tor_assert(consensus_info->n_voters > 0);

  smartlist_add_asprintf(chunks, "shared-random-version 1 shared-random");
  smartlist_add_asprintf(chunks, "valid-until %s %s", "2420-11-09", "00:00:00");
  smartlist_add_asprintf(chunks, "protocol-phase %s", "night");
  smartlist_add_asprintf(chunks, "directory-signature aaaa");

  output = smartlist_join_strings(chunks, "\n", 0, NULL);

  return output;
}

int
shared_random_compute_sr_doc(consensus_creation_helper_t *consensus_info)
{
  char *sr_doc_body = NULL;
  shared_random_doc_t *sr_doc = NULL;

  sr_doc_body = compute_sr_doc_body(consensus_info);
  if (!sr_doc_body) {
    log_warn(LD_DIR, "Couldn't generate an SR doc body.");
    goto err;
  }

  sr_doc = parse_sr_doc_from_string(sr_doc_body, NULL);
  if (!sr_doc) {
    log_warn(LD_DIR, "Failed to parse SR doc we generated.");
    goto err;
  }

  consensus_info->pending[FLAV_SHARED_RANDOM].body = sr_doc_body;
  consensus_info->pending[FLAV_SHARED_RANDOM].u.sr_doc = sr_doc;

  return 0;

 err:
  tor_free(sr_doc_body);
  sr_doc_free(sr_doc);

  return -1;
}
