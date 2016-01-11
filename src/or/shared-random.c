/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared-random.c
 *
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 *
 * \details
 *
 * This file implements the dirauth-only commit-and-reveal protocol specified
 * by proposal #250. The protocol has two phases (sr_phase_t): the commitment
 * phase and the reveal phase (see get_sr_protocol_phase()).
 *
 * During the protocol, directory authorities keep state in memory (using
 * sr_state_t) and in disk (using sr_disk_state_t). The synchronization between
 * these two data structures happens in disk_state_update() and
 * disk_state_parse().
 *
 * Here is a rough protocol outline:
 *
 *      1) In the beginning of the commitment phase, dirauths generate a
 *         commitment/reveal value for the current protocol run (see
 *         new_protocol_run() and sr_generate_our_commit()).
 *
 *      2) During voting, dirauths publish their commits in their votes
 *         depending on the current phase.  Dirauths also include the two
 *         latest shared random values (SRV) in their votes.
 *         (see sr_get_string_for_vote())
 *
 *      3) Upon receiving a commit from a vote, authorities parse it, verify
 *         it, and attempt to save any new commitment or reveal information in
 *         their state file (see extract_shared_random_commits() and
 *         sr_handle_received_commits()).  They also parse SRVs from votes to
 *         decide which SRV should be included in the final consensus (see
 *         extract_shared_random_srvs()).
 *
 *      3) After voting is done, we count the SRVs we extracted from the votes,
 *         to find the one voted by the majority of dirauths which should be
 *         included in the final consensus (see get_majority_srv_from_votes()).
 *         If an appropriate SRV is found, it is embedded in the consensus (see
 *         sr_get_string_for_consensus()).
 *
 *      4) At the end of the reveal phase, dirauths compute a fresh SRV for the
 *         day using the active commits (see sr_compute_srv()).  This new SRV
 *         is embedded in the votes as described above.
 *
 * Some more notes:
 *
 * - To support rebooting authorities and to avoid double voting, each dirauth
 *   saves the current state of the protocol on disk so that it can resume
 *   normally in case of reboot. The disk state (sr_disk_state_t) is managed by
 *   shared-random-state.c:state_query() and we go to extra lengths to ensure
 *   that the state is flushed on disk everytime we receive any useful
 *   information like commits or SRVs.
 *
 * - When we receive a commit from a vote, we examine it to see if it's useful
 *   to us and whether it's appropriate to receive it according to the current
 *   phase of the protocol (see should_keep_commit()). If the commit is useful
 *   to us, we save it in our disk state using save_commit_to_state().  When we
 *   receive the reveal information corresponding to a commitment, we verify
 *   that they indeed match using verify_commit_and_reveal().
 *
 * - We treat consensuses as the ground truth, so everytime we generate a new
 *   consensus we update our SR state accordingly even if our local view was
 *   different (see sr_act_post_consensus()).
 *
 * - After a consensus has been composed, the SR protocol state gets prepared
 *   for the next voting session using sr_state_update(). That function takes
 *   care of housekeeping and also rotates the SRVs and commits in case a new
 *   protocol run is coming up. We also call sr_state_update() on bootup (in
 *   sr_state_init()), to prepare the state for the very first voting session.
 *
 * Terminology:
 *
 * - "Commitment" is the commitment value of the commit-and-reveal protocol.
 *
 * - "Reveal" is the reveal value of the commit-and-reveal protocol.
 *
 * - "Commit" is a struct (sr_commit_t) that contains a commitment value and
 *    optionally also a corresponding reveal value.
 *
 * - "SRV" is the Shared Random Value that gets generated as the result of the
 *   commit-and-reveal protocol.
 **/

#define SHARED_RANDOM_PRIVATE

#include "or.h"
#include "shared-random.h"
#include "config.h"
#include "confparse.h"
#include "networkstatus.h"
#include "routerkeys.h"
#include "router.h"
#include "routerlist.h"
#include "shared-random-state.h"

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const char *rsa_identity_fpr)
{
  sr_commit_t *commit;

  tor_assert(rsa_identity_fpr);

  commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  strlcpy(commit->rsa_identity_fpr, rsa_identity_fpr,
          sizeof(commit->rsa_identity_fpr));
  return commit;
}

/* Issue a log message describing <b>commit</b>. */
static void
commit_log(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_debug(LD_DIR, "SR: Commit from %s", commit->rsa_identity_fpr);

  if (commit->commit_ts >= 0) {
    log_debug(LD_DIR, "SR: Commit: [TS: %ld] [H(R): %s...]",
             commit->commit_ts, hex_str(commit->hashed_reveal, 5));
  }

  if (commit->reveal_ts >= 0) {
    log_debug(LD_DIR, "SR: Reveal: [TS: %ld] [H(RN): %s...] [R: %s]",
              commit->reveal_ts, hex_str(commit->random_number, 5),
              commit->encoded_reveal);
  } else {
    log_debug(LD_DIR, "SR: Reveal: UNKNOWN");
  }
}

/* Return true iff the commit contains an encoded reveal value. */
STATIC int
commit_has_reveal_value(const sr_commit_t *commit)
{
  return !tor_mem_is_zero(commit->encoded_reveal,
                          sizeof(commit->encoded_reveal));
}

/* Parse the encoded commit. The format is:
 *    base64-encode( TIMESTAMP || H(REVEAL) )
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
STATIC int
commit_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  size_t offset = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_COMMIT_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_COMMIT_BASE64_LEN) {
    /* This means that if we base64 decode successfully the reveiced commit,
     * we'll end up with a bigger decoded commit thus unusable. */
    goto error;
  }

  /* Decode our encoded commit. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of a commit. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Commit from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len < SR_COMMIT_LEN) {
    log_warn(LD_BUG, "SR: Commit from authority %s decoded length is "
                     "too small (%d vs %d).",
             commit->rsa_identity_fpr, decoded_len, SR_COMMIT_LEN);
    goto error;
  }

  /* First is the timestamp (8 bytes). */
  commit->commit_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  offset += sizeof(uint64_t);
  /* Next is hashed reveal. */
  memcpy(commit->hashed_reveal, b64_decoded + offset,
         sizeof(commit->hashed_reveal));
  /* Copy the base64 blob to the commit. Useful for voting. */
  strncpy(commit->encoded_commit, encoded, sizeof(commit->encoded_commit));

  return 0;

 error:
  return -1;
}

/* Parse the b64 blob at <b>encoded</b> containing reveal information and
 * store the information in-place in <b>commit</b>. Return 0 on success else
 * a negative value. */
STATIC int
reveal_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_REVEAL_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_REVEAL_BASE64_LEN) {
    /* This means that if we base64 decode successfully the received reveal
     * value, we'll end up with a bigger decoded value thus unusable. */
    goto error;
  }

  /* Decode our encoded reveal. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of our reveal. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Reveal from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len < SR_REVEAL_LEN) {
    log_warn(LD_BUG, "SR: Reveal from authority %s decoded length is "
             "too small.",
             commit->rsa_identity_fpr);
    goto error;
  }

  commit->reveal_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  /* Copy the last part, the random value. */
  memcpy(commit->random_number, b64_decoded + 8,
         sizeof(commit->random_number));
  /* Also copy the whole message to use during verification */
  strncpy(commit->encoded_reveal, encoded, sizeof(commit->encoded_reveal));

  return 0;

 error:
  return -1;
}

/* Encode a reveal element using a given commit object to dst which is a
 * buffer large enough to put the base64-encoded reveal construction. The
 * format is as follow:
 *     REVEAL = base64-encode( TIMESTAMP || H(RN) )
 * Return base64 encoded length on success else a negative value.
 */
STATIC int
reveal_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset = 0;
  char buf[SR_REVEAL_LEN] = {0};

  tor_assert(commit);
  tor_assert(dst);

  set_uint64(buf, tor_htonll((uint64_t) commit->commit_ts));
  offset += 8;
  memcpy(buf + offset, commit->random_number,
         sizeof(commit->random_number));

  /* Let's clean the buffer and then b64 encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Encode the given commit object to dst which is a buffer large enough to
 * put the base64-encoded commit. The format is as follow:
 *     COMMIT = base64-encode( TIMESTAMP || H(H(RN)) )
 * Return base64 encoded length on success else a negative value.
 */
STATIC int
commit_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset = 0;
  char buf[SR_COMMIT_LEN] = {0};

  tor_assert(commit);
  tor_assert(dst);

  /* First is the timestamp (8 bytes). */
  set_uint64(buf, tor_htonll((uint64_t) commit->commit_ts));
  offset += sizeof(uint64_t);
  /* and then the hashed reveal. */
  memcpy(buf + offset, commit->hashed_reveal,
         sizeof(commit->hashed_reveal));

  /* Clean the buffer and then b64 encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Cleanup both our global state and disk state. */
static void
sr_cleanup(void)
{
  sr_state_free();
}

/* Using <b>commit</b>, return a newly allocated string containing the commit
 * information that should be used during SRV calculation. It's the caller
 * responsibility to free the memory. Return NULL if this is not a commit to be
 * used for SRV calculation. */
static char *
get_srv_element_from_commit(const sr_commit_t *commit)
{
  char *element;
  tor_assert(commit);

  if (!commit_has_reveal_value(commit)) {
    return NULL;
  }

  tor_asprintf(&element, "%s%s", commit->rsa_identity_fpr,
               commit->encoded_reveal);
  return element;
}

/* Return a srv object that is built with the construction:
 *    SRV = SHA3-256("shared-random" | INT_8(reveal_num) |
 *                   INT_8(version) | HASHED_REVEALS | previous_SRV)
 * This function cannot fail. */
static sr_srv_t *
generate_srv(const char *hashed_reveals, uint8_t reveal_num,
             const sr_srv_t *previous_srv)
{
  char msg[DIGEST256_LEN + SR_SRV_MSG_LEN] = {0};
  size_t offset = 0;
  sr_srv_t *srv;

  tor_assert(hashed_reveals);

  /* Add the invariant token. */
  memcpy(msg, SR_SRV_TOKEN, SR_SRV_TOKEN_LEN);
  offset += SR_SRV_TOKEN_LEN;
  set_uint8(msg + offset, reveal_num);
  offset += 1;
  set_uint8(msg + offset, SR_PROTO_VERSION);
  offset += 1;
  memcpy(msg + offset, hashed_reveals, DIGEST256_LEN);
  offset += DIGEST256_LEN;
  if (previous_srv != NULL) {
    memcpy(msg + offset, previous_srv->value, sizeof(previous_srv->value));
  }

  /* Ok we have our message and key for the HMAC computation, allocate our
   * srv object and do the last step. */
  srv = tor_malloc_zero(sizeof(*srv));
  crypto_digest256((char *) srv->value, msg, sizeof(msg), SR_DIGEST_ALG);
  srv->num_reveals = reveal_num;

  log_debug(LD_DIR, "SR: Generated SRV: %s",
            hex_str((const char *) srv->value, HEX_DIGEST256_LEN));
  return srv;
}

/* Free a commit object. */
void
sr_commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  /* Make sure we do not leave OUR random number in memory. */
  memwipe(commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/* Generate the commitment/reveal value for the protocol run starting at
 * <b>timestamp</b>. <b>my_rsa_cert</b> is our authority RSA certificate. */
sr_commit_t *
sr_generate_our_commit(time_t timestamp, authority_cert_t *my_rsa_cert)
{
  sr_commit_t *commit = NULL;
  char fingerprint[FINGERPRINT_LEN+1];

  tor_assert(my_rsa_cert);

  /* Get our RSA identity fingerprint */
  if (crypto_pk_get_fingerprint(my_rsa_cert->identity_key,
                                fingerprint, 0) < 0) {
    goto error;
  }

  /* New commit with our identity key. */
  commit = commit_new(fingerprint);

  {
    int ret;
    char raw_rand[SR_RANDOM_NUMBER_LEN] = {0};
    /* Generate the reveal random value */
    crypto_rand(raw_rand, sizeof(commit->random_number));
    /* Hash our random value in order to avoid sending the raw bytes of our
     * PRNG to the network. */
    ret = crypto_digest256(commit->random_number, raw_rand,
                           sizeof(raw_rand), SR_DIGEST_ALG);
    memwipe(raw_rand, 0, sizeof(raw_rand));
    if (ret < 0) {
      goto error;
    }
  }
  commit->commit_ts = commit->reveal_ts = timestamp;

  /* Now get the base64 blob that corresponds to our reveal */
  if (reveal_encode(commit, commit->encoded_reveal,
                    sizeof(commit->encoded_reveal)) < 0) {
    log_err(LD_DIR, "SR: Unable to encode our reveal value!");
    goto error;
  }

  /* Now let's create the commitment */
  tor_assert(commit->alg == SR_DIGEST_ALG);
  /* The invariant length is used here since the encoded reveal variable
   * has an extra byte added for the NULL terminated byte. */
  if (crypto_digest256(commit->hashed_reveal, commit->encoded_reveal,
                       SR_REVEAL_BASE64_LEN, commit->alg) < 0) {
    goto error;
  }

  /* Now get the base64 blob that corresponds to our commit. */
  if (commit_encode(commit, commit->encoded_commit,
                    sizeof(commit->encoded_commit)) < 0) {
    log_err(LD_DIR, "SR: Unable to encode our commit value!");
    goto error;
  }

  log_debug(LD_DIR, "SR: Generated our commitment:");
  commit_log(commit);
  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Compare commit identity RSA fingerprint and return the result. This
 * should exclusively be used by smartlist_sort(). */
static int
compare_commit_identity_(const void **_a, const void **_b)
{
    return strcmp(((sr_commit_t *)*_a)->rsa_identity_fpr,
                  ((sr_commit_t *)*_b)->rsa_identity_fpr);
}

/* Compute the shared random value based on the active commits in our state. */
void
sr_compute_srv(void)
{
  size_t reveal_num = 0;
  char *reveals = NULL;
  smartlist_t *chunks, *commits;
  digestmap_t *state_commits;

  /* Computing a shared random value in the commit phase is very wrong. This
   * should only happen at the very end of the reveal phase when a new
   * protocol run is about to start. */
  tor_assert(sr_state_get_phase() == SR_PHASE_REVEAL);
  state_commits = sr_state_get_commits();

  commits = smartlist_new();
  chunks = smartlist_new();

  /* We must make a list of commit ordered by authority fingerprint in
   * ascending order as specified by proposal 250. */
  DIGESTMAP_FOREACH(state_commits, key, sr_commit_t *, c) {
    smartlist_add(commits, c);
  } DIGESTMAP_FOREACH_END;
  smartlist_sort(commits, compare_reveal_);

  /* Now for each commit for that sorted list in ascending order, we'll
   * build the element for each authority that needs to go into the srv
   * computation. */
  SMARTLIST_FOREACH_BEGIN(commits, const sr_commit_t *, c) {
    char *element = get_srv_element_from_commit(c);
    if (element) {
      smartlist_add(chunks, element);
      reveal_num++;
    }
  } SMARTLIST_FOREACH_END(c);
  smartlist_free(commits);

  {
    /* Join all reveal values into one giant string that we'll hash so we
     * can generated our shared random value. */
    sr_srv_t *current_srv;
    char hashed_reveals[DIGEST256_LEN];
    reveals = smartlist_join_strings(chunks, "", 0, NULL);
    SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
    smartlist_free(chunks);
    if (crypto_digest256(hashed_reveals, reveals, strlen(reveals),
                         SR_DIGEST_ALG) < 0) {
      goto end;
    }
    tor_assert(reveal_num < UINT8_MAX);
    current_srv = generate_srv(hashed_reveals, (uint8_t) reveal_num,
                               sr_state_get_previous_srv());
    sr_state_set_current_srv(current_srv);
    /* We have a fresh SRV, flag our state. */
    sr_state_set_fresh_srv();
  }

 end:
  tor_free(reveals);
}

/* Parse a list of arguments from a SRV value either from a vote, consensus
 * or from our disk state and return a newly allocated srv object. NULL is
 * returned on error.
 *
 * The arguments' order:
 *    num_reveals, value
 */
sr_srv_t *
sr_parse_srv(smartlist_t *args)
{
  char *value;
  int num_reveals, ok;
  sr_srv_t *srv = NULL;

  tor_assert(args);

  if (smartlist_len(args) < 2) {
    goto end;
  }

  /* First argument is the number of reveal values */
  num_reveals = tor_parse_long(smartlist_get(args, 0),
                               10, 0, INT32_MAX, &ok, NULL);
  if (!ok) {
    goto end;
  }
  srv = tor_malloc_zero(sizeof(*srv));
  srv->num_reveals = num_reveals;

  /* Second and last argument is the shared random value it self. */
  value = smartlist_get(args, 1);
  base16_decode((char *) srv->value, sizeof(srv->value), value,
                HEX_DIGEST256_LEN);
 end:
  return srv;
}

/* Parse a commit from a vote or from our disk state and return a newly
 * allocated commit object. NULL is returned on error.
 *
 * The commit's data is in <b>args</b> and the order matters very much:
 *  algname, RSA fingerprint, commit value[, reveal value]
 */
sr_commit_t *
sr_parse_commit(smartlist_t *args)
{
  char *value;
  digest_algorithm_t alg;
  const char *rsa_identity_fpr;
  sr_commit_t *commit = NULL;

  if (smartlist_len(args) < 3) {
    goto error;
  }

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_BUG, "SR: Commit algorithm %s is not recognized.",
             escaped(value));
    goto error;
  }

  /* Second argument is the RSA fingerprint of the auth */
  rsa_identity_fpr = smartlist_get(args, 1);

  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(rsa_identity_fpr);

  /* Third argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 2);
  if (commit_decode(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fourth argument is the revealed value. */
  if (smartlist_len(args) > 3) {
    value = smartlist_get(args, 3);
    if (reveal_decode(value, commit) < 0) {
      goto error;
    }
  }

  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Initialize shared random subsystem. This MUST be called early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  return sr_state_init(save_to_disk, 1);
}

/* Save our state to disk and cleanup everything. */
void
sr_save_and_cleanup(void)
{
  sr_state_save();
  sr_cleanup();
}
