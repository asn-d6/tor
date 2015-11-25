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
 * This file implements the dirauth-only commit-and-reveal protocol
 * specified by proposal #250. The protocol has two phases (sr_phase_t): the
 * commitment phase and the reveal phase.
 *
 * The rough procedure is:
 *
 *      1) In the beginning of the commitment phase, dirauths generate a
 *         commitment/reveal value for the current protocol run (see
 *         new_protocol_run()).
 *
 *      2) Dirauths publish commitment/reveal values in their votes
 *         depending on the current phase (see sr_get_string_for_vote()).
 *
 *      3) Upon receiving a commit from a vote, authorities parse it, verify it,
 *         and attempt to save any new commitment or reveal information in their
 *         state file (see sr_handle_received_commit()).
 *
 *      4) In the end of the reveal phase, dirauths compute the random value
 *         of the day using the active reveal values (see sr_compute_srv()).
 *
 * To better support rebooting authorities we save the current state of the
 * shared random protocol in disk so that authorities can resume on the
 * protocol if they have to reboot.
 *
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

/* String representation of a shared random value status. */
static const char *srv_status_str[] = { "fresh", "non-fresh" };

static void save_commit_to_state(sr_commit_t *commit);

/* Return a string representation of a srv status. */
const char *
sr_get_srv_status_str(sr_srv_status_t status)
{
  switch (status) {
  case SR_SRV_STATUS_FRESH:
  case SR_SRV_STATUS_NONFRESH:
    return srv_status_str[status];
  default:
    /* Unknown status shouldn't be possible. */
    tor_assert(0);
  }
}

/* Return a status value from a string. */
sr_srv_status_t
sr_get_srv_status_from_str(const char *name)
{
  unsigned int i;
  sr_srv_status_t status = -1;

  tor_assert(name);

  for (i = 0; i < ARRAY_LENGTH(srv_status_str); i++) {
    if (!strcmp(name, srv_status_str[i])) {
      status = i;
      break;
    }
  }
  return status;
}

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const ed25519_public_key_t *identity,
           const char *rsa_identity_fpr)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  tor_assert(identity);
  memcpy(&commit->auth_identity, identity, sizeof(commit->auth_identity));
  /* This call can't fail. */
  ed25519_public_to_base64(commit->auth_fingerprint, identity);
  strlcpy(commit->rsa_identity_fpr, rsa_identity_fpr, sizeof(commit->rsa_identity_fpr));
  return commit;
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

/* Issue a log message describing <b>commit</b>. */
static void
commit_log(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_warn(LD_DIR, "[SR] \t Commit of %s [transmitted by %s]",
           commit->auth_fingerprint,
           commit->rsa_identity_fpr);

  if (commit->commit_ts >= 0) {
    log_warn(LD_DIR, "[SR] \t C: [TS: %u] [H(R): %s...]",
             (unsigned) commit->commit_ts,
             hex_str(commit->hashed_reveal, 5));
  }

  if (commit->reveal_ts >= 0) {
    log_warn(LD_DIR, "[SR] \t R: [TS: %u] [RN: %s...] [R: %s...]",
             (unsigned) commit->reveal_ts,
             hex_str((const char *) commit->random_number, 5),
             hex_str(commit->encoded_reveal, 5));
  } else {
    log_warn(LD_DIR, "[SR] \t R: UNKNOWN");
  }
}

/* Make sure that the commitment and reveal information in <b>commit</b>
 * match. If they match return 0, return -1 otherwise. This function MUST be
 * used everytime we receive a new reveal value. */
static int
verify_commit_and_reveal(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_warn(LD_DIR, "[SR] Validating commit from %s",
           commit->auth_fingerprint);

  /* Check that the timestamps match. */
  if (commit->commit_ts != commit->reveal_ts) {
    log_warn(LD_DIR, "[SR] Commit timestamp %ld doesn't match reveal "
                     "timestamp %ld", commit->commit_ts, commit->reveal_ts);
    goto invalid;
  }

  /* Verify that the hashed_reveal received in the COMMIT message, matches
   * the reveal we just received. */
  {
    /* We first hash the reveal we just received. */
    char received_hashed_reveal[sizeof(commit->hashed_reveal)];
    if (crypto_digest256(received_hashed_reveal,
                         commit->encoded_reveal,
                         sizeof(commit->encoded_reveal),
                         DIGEST_SHA256) < 0) {
      /* Unable to digest the reveal blob, this is unlikely. */
      goto invalid;
    }
    /* Now compare that with the hashed_reveal we received in COMMIT. */
    if (fast_memneq(received_hashed_reveal, commit->hashed_reveal,
                    sizeof(received_hashed_reveal))) {
      log_warn(LD_DIR, "[SR] \t Reveal DOES NOT match!");

      log_warn(LD_DIR, "[SR] \t Orig R: %s",
               hex_str((const char *) commit->hashed_reveal, 5));

      log_warn(LD_DIR, "[SR] \t Recv R: %s",
               hex_str((const char *) received_hashed_reveal, 5));

      commit_log(commit);
      goto invalid;
    }
  }

  return 0;
 invalid:
  return -1;
}

STATIC int
commit_has_reveal_value(const sr_commit_t *commit)
{
  return !tor_mem_is_zero(commit->encoded_reveal,
                          sizeof(commit->encoded_reveal));
}

/* Parse the encoded commit. The format is:
 *    base64-encode( H(REVEAL) || TIMESTAMP )
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
STATIC int
commit_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  size_t offset = 0;
  /* Needs an extra byte for the base64 decode calculation matches the
   * binary length once decoded. */
  char b64_decoded[SR_COMMIT_LEN + 2]; /* XXXX why + 2 */

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
    log_warn(LD_DIR, "[SR] Commitment can't be decoded %s.", encoded);
    goto error;
  }

  if (decoded_len < SR_COMMIT_LEN) {
    log_warn(LD_DIR, "[SR] Commitment too small.");
    goto error;
  }

  /* First is the hashed reaveal. */
  memcpy(commit->hashed_reveal, b64_decoded, sizeof(commit->hashed_reveal));
  offset += sizeof(commit->hashed_reveal);
  /* Next is timestamp. */
  commit->commit_ts = (time_t) tor_ntohll(get_uint64(b64_decoded + offset));
  /* Copy the base64 blob to the commit. Useful for voting. */
  strncpy(commit->encoded_commit, encoded, sizeof(commit->encoded_commit));

  return 0;
error:
  return -1;
}

/* Parse the b64 blob at <b>encoded</b> containin reveal information
   and store the information in-place in <b>commit</b>. */
STATIC int
reveal_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  /* Needs two extra bytes for the base64 decode calculation matches the
   * binary length once decoded. */
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
    log_warn(LD_DIR, "[SR] Reveal value can't be decoded.");
    goto error;
  }

  if (decoded_len < SR_REVEAL_LEN) {
    log_warn(LD_DIR, "[SR] Reveal value too small.");
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
 *     REVEAL = base64-encode( TIMESTAMP || RN )
 * Return 0 on success else a negative value.
 */
STATIC int
reveal_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset = 0;
  char buf[SR_REVEAL_LEN];

  tor_assert(commit);
  tor_assert(dst);

  memset(buf, 0, sizeof(buf));

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
 *     COMMIT = base64-encode( H(REVEAL) || TIMESTAMP )
 */
STATIC int
commit_encode(sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset = 0;
  char buf[SR_COMMIT_LEN];

  tor_assert(commit);
  tor_assert(dst);

  memset(buf, 0, sizeof(buf));

  /* First is the hashed reveal. */
  memcpy(buf, commit->hashed_reveal,
         sizeof(commit->hashed_reveal));
  offset += sizeof(commit->hashed_reveal);
  /* and then the timestamp */
  set_uint64(buf + offset, tor_htonll((uint64_t) commit->commit_ts));

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

/* Initialize shared random subsystem. This MUST be call early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  return sr_state_init(save_to_disk);
}

/* Save our state to disk and cleanup everything. */
void
sr_save_and_cleanup(void)
{
  sr_state_save();
  sr_cleanup();
}

/** Generate the commitment/reveal value for the protocol run starting
 *  at <b>timestamp</b>. If <b>my_cert</b> is provided use it as our
 *  authority certificate (used in unittests). */
sr_commit_t *
sr_generate_our_commitment(time_t timestamp, authority_cert_t *my_rsa_cert)
{
  sr_commit_t *commit = NULL;
  char fingerprint[FINGERPRINT_LEN+1];
  const ed25519_public_key_t *identity_key;

  tor_assert(my_rsa_cert);

  /* Get our ed25519 master key */
  identity_key = get_master_identity_key();
  tor_assert(identity_key);

  /* Get our RSA identity fingerprint */
  if (crypto_pk_get_fingerprint(my_rsa_cert->identity_key,
                                fingerprint, 0) < 0) {
    goto error;
  }

  /* New commit with our identity key. */
  commit = commit_new(identity_key, fingerprint);

  {
    int ret;
    char raw_rand[SR_RANDOM_NUMBER_LEN];
    /* Generate the reveal random value */
    if (crypto_rand(raw_rand, sizeof(commit->random_number)) < 0) {
      log_err(LD_REND, "[SR] Unable to generate reveal random value!");
      goto error;
    }
    /* Hash our random value in order to avoid sending the raw bytes of our
     * PRNG to the network. */
    ret = crypto_digest256(commit->random_number, raw_rand,
                           sizeof(raw_rand), DIGEST_SHA256);
    memwipe(raw_rand, 0, sizeof(raw_rand));
    if (ret < 0) {
      goto error;
    }
  }
  commit->commit_ts = commit->reveal_ts = timestamp;

  /* Now get the base64 blob that corresponds to our reveal */
  if (reveal_encode(commit, commit->encoded_reveal,
                    sizeof(commit->encoded_reveal)) < 0) {
    log_err(LD_REND, "[SR] Unable to encode the reveal value!");
    goto error;
  }

  /* Now let's create the commitment */

  switch (commit->alg) {
  case DIGEST_SHA1:
  case DIGEST_SHA512:
    tor_assert(0);
  case DIGEST_SHA256:
    /* Only sha256 is supported and the default. */
  default:
    if (crypto_digest256(commit->hashed_reveal, commit->encoded_reveal,
                         sizeof(commit->encoded_reveal),
                         DIGEST_SHA256) < 0) {
      goto error;
    }
    break;
  }

  /* Now get the base64 blob that corresponds to our commit. */
  if (commit_encode(commit, commit->encoded_commit,
                    sizeof(commit->encoded_commit)) < 0) {
    log_err(LD_REND, "[SR] Unable to encode the commit value!");
    goto error;
  }

  log_warn(LD_DIR, "[SR] Generated our commitment:");
  commit_log(commit);
  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Using <b>commit</b>, return a newly allocated string containing the
 * authority identity fingerprint concatenated with its encoded reveal
 * value. It's the caller responsibility to free the memory. This can't fail
 * thus a valid string is always returned. */
static char *
get_srv_element_from_commit(const sr_commit_t *commit)
{
  char *element;
  tor_assert(commit);
  tor_asprintf(&element, "%s%s", commit->auth_fingerprint,
               commit->encoded_reveal);
  return element;
}

/* Return a srv object that is built with the construction:
 *    SRV = HMAC(HASHED_REVEALS, "shared-random" | INT_8(reveal_num) |
 *                               INT_8(version) | previous_SRV)
 * This function cannot fail. */
static sr_srv_t *
generate_srv(const char *hashed_reveals, uint8_t reveal_num,
             const sr_srv_t *previous_srv)
{
  char msg[SR_SRV_HMAC_MSG_LEN];
  size_t offset = 0;
  sr_srv_t *srv;

  tor_assert(hashed_reveals);
  /* Specification requires at least 3 authorities are needed. */
  tor_assert(reveal_num >= 3);

  /* Very important here since we might not have a previous shared random
   * value so make sure we all have the content at first. */
  memset(msg, 0, sizeof(msg));

  /* Add the invariant token. */
  memcpy(msg, SR_SRV_TOKEN, SR_SRV_TOKEN_LEN);
  offset += SR_SRV_TOKEN_LEN;
  set_uint8(msg + offset, reveal_num);
  offset += 1;
  set_uint8(msg + offset, SR_PROTO_VERSION);
  offset += 1;
  if (previous_srv != NULL) {
    memcpy(msg + offset, previous_srv->value,
           sizeof(previous_srv->value));
    /* XXX: debugging. */
    log_warn(LD_DIR, "[SR] \t Previous SRV added: %s",
             hex_str((const char *) previous_srv->value, 5));
  }

  /* Ok we have our message and key for the HMAC computation, allocate our
   * srv object and do the last step. */
  srv = tor_malloc_zero(sizeof(*srv));
  crypto_hmac_sha256((char *) srv->value,
                     hashed_reveals, DIGEST256_LEN,
                     msg, sizeof(msg));
  srv->status = SR_SRV_STATUS_FRESH;

  /* XXX: debugging. */
  log_warn(LD_DIR, "[SR] Computed shared random details:");
  log_warn(LD_DIR, "[SR] \t Key: %s, NUM: %u",
           hex_str(hashed_reveals, HEX_DIGEST256_LEN), reveal_num);
  log_warn(LD_DIR, "[SR] \t Msg: %s", hex_str(msg, 10));
  log_warn(LD_DIR, "[SR] \t Final SRV: %s",
           hex_str((const char *) srv->value, HEX_DIGEST256_LEN));
  return srv;
}

/* Return a srv object that constructed with the disaster mode
 * specification. It's as follow:
 *    HMAC(previous_SRV, "shared-random-disaster")
 * This function cannot fail. */
static sr_srv_t *
generate_srv_disaster(sr_srv_t *previous_srv)
{
  char key[DIGEST256_LEN];
  sr_srv_t *srv = tor_malloc_zero(sizeof(*srv));
  static const char *invariant = "shared-random-disaster";

  log_warn(LD_DIR, "[SR] Computing distaster shared random value.");

  if (previous_srv) {
    memcpy(key, previous_srv->value, sizeof(key));
  } else {
    memset(key, 0, sizeof(key));
  }

  crypto_hmac_sha256((char *) srv->value, key, sizeof(key),
                     invariant, strlen(invariant));
  srv->status = SR_SRV_STATUS_NONFRESH;
  return srv;
}

/* Compare commit identity fingerprint and return the result. This should
 * exclusively be used by smartlist_sort. */
static int
compare_commit_identity_(const void **_a, const void **_b)
{
  return strcmp(((sr_commit_t *)*_a)->auth_fingerprint,
                ((sr_commit_t *)*_b)->auth_fingerprint);
}

/** Compute the shared random value based on the reveals we have in the
 * given <b>state</b>. */
void
sr_compute_srv(void)
{
  size_t reveal_num;
  char *reveals = NULL;
  smartlist_t *chunks, *commits;
  digest256map_t *state_commits;

  /* Computing a shared random value in the commit phase is very wrong. This
   * should only happen at the very end of the reveal phase when a new
   * protocol run is about to start. */
  tor_assert(sr_state_get_phase() == SR_PHASE_REVEAL);
  state_commits = sr_state_get_commits();

  /* XXX: Let's make sure those conditions to compute an SRV are solid and
   * cover all cases. While writing this I'm still unsure of those. */
  reveal_num = digest256map_size(state_commits);
  tor_assert(reveal_num < UINT8_MAX);

  /* One single value means that it's only ours so do not compute a disaster
   * shared random value. */
  if (reveal_num == 1) {
    goto end;
  }
  /* Make sure we have enough reveal values and if not, generate the
   * disaster srv value and stop right away. */
  if (reveal_num < SR_SRV_MIN_REVEAL) {
    sr_srv_t *disaster_srv =
      generate_srv_disaster(sr_state_get_previous_srv());
    sr_state_set_current_srv(disaster_srv);
    goto end;
  }

  commits = smartlist_new();
  chunks = smartlist_new();

  /* We must make a list of commit ordered by authority fingerprint in
   * ascending order as specified by proposal 250. */
  DIGEST256MAP_FOREACH(state_commits, key, sr_commit_t *, c) {
    smartlist_add(commits, c);
  } DIGEST256MAP_FOREACH_END;
  smartlist_sort(commits, compare_commit_identity_);

  /* Now for each commit for that sorted list in ascending order, we'll
   * build the element for each authority that needs to go into the srv
   * computation. */
  SMARTLIST_FOREACH_BEGIN(commits, const sr_commit_t *, c) {
    char *element = get_srv_element_from_commit(c);
    smartlist_add(chunks, element);
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
                         DIGEST_SHA256) < 0) {
      log_warn(LD_DIR, "[SR] Unable to hash the reveals. Stopping.");
      goto end;
    }
    current_srv = generate_srv(hashed_reveals, (uint8_t) reveal_num,
                               sr_state_get_previous_srv());
    sr_state_set_current_srv(current_srv);
  }

 end:
  tor_free(reveals);
}

/* Given <b>commit</b> give the line that we should place in our votes.
 * It's the responsibility of the caller to free the string. */
static char *
get_vote_line_from_commit(const sr_commit_t *commit)
{
  char *vote_line = NULL;
  sr_phase_t current_phase = sr_state_get_phase();
  static const char *commit_str_key = "shared-rand-commitment";

  log_warn(LD_DIR, "Encoding commit for vote:");
  commit_log(commit);

  switch (current_phase) {
  case SR_PHASE_COMMIT:
    tor_asprintf(&vote_line, "%s %s %s %s\n",
                 commit_str_key,
                 commit->auth_fingerprint,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->encoded_commit);
    break;
  case SR_PHASE_REVEAL:
  {
    /* Send a reveal value for this commit if we have one. */
    const char *reveal_str = commit->encoded_reveal;
    if (tor_mem_is_zero(commit->encoded_reveal,
                        sizeof(commit->encoded_reveal))) {
      reveal_str = "";
    }
    tor_asprintf(&vote_line, "%s %s %s %s %s\n",
                 commit_str_key,
                 commit->auth_fingerprint,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->encoded_commit, reveal_str);
    break;
  }
  default:
    tor_assert(0);
  }

  return vote_line;
}

/* Return a heap allocated string that contains the SRV line(s) that should
 * be put in a vote or consensus. Caller must free the returned string.
 * Empty string is returned if there are no SRV. */
static char *
get_srv_ns_lines(void)
{
  char *srv_line = NULL, *srv_str;
  char srv_hash_encoded[HEX_DIGEST256_LEN + 1];
  smartlist_t *lines = smartlist_new();
  sr_srv_t *srv;
  static const char *prev_str_key = "shared-rand-previous-value";
  static const char *cur_str_key = "shared-rand-current-value";

  /* Compute the previous srv value if one. */
  srv = sr_state_get_previous_srv();
  if (srv != NULL) {
    base16_encode(srv_hash_encoded, sizeof(srv_hash_encoded),
                  (const char *) srv->value, sizeof(srv->value));
    tor_asprintf(&srv_line, "%s %s %s\n", prev_str_key,
                 sr_get_srv_status_str(srv->status), srv_hash_encoded);
    smartlist_add(lines, srv_line);
    log_warn(LD_DIR, "[SR] \t Previous SRV: %s", srv_line);
  }
  /* Compute current srv value if one. */
  srv = sr_state_get_current_srv();
  if (srv != NULL) {
    base16_encode(srv_hash_encoded, sizeof(srv_hash_encoded),
                  (const char *) srv->value, sizeof(srv->value));
    tor_asprintf(&srv_line, "%s %s %s\n", cur_str_key,
                 sr_get_srv_status_str(srv->status), srv_hash_encoded);
    smartlist_add(lines, srv_line);
    log_warn(LD_DIR, "[SR] \t Current SRV: %s", srv_line);
  }
  srv_str = smartlist_join_strings(lines, "", 0, NULL);
  SMARTLIST_FOREACH(lines, char *, s, tor_free(s));
  smartlist_free(lines);
  return srv_str;
}

/* Return a heap-allocated string containing commits that should be put in
 * the votes. It's the responsibility of the caller to free the string.
 * This always return a valid string, either empty or with line(s). */
char *
sr_get_string_for_vote(void)
{
  char *vote_str = NULL;
  digest256map_t *state_commits;
  smartlist_t *chunks = smartlist_new();
  const or_options_t *options = get_options();

  /* Are we participating in the protocol? */
  if (!options->VoteSharedRandom) {
    /* chunks is an empty list at this point which will result in an empty
     * string at the end. */
    goto end;
  }

  log_warn(LD_DIR, "[SR] Sending out vote string:");

  /* First line, put in the vote the participation flag. */
  {
    char *sr_flag_line;
    static const char *sr_flag_key = "shared-rand-participate";
    tor_asprintf(&sr_flag_line, "%s\n", sr_flag_key);
    smartlist_add(chunks, sr_flag_line);
  }

  /* In our vote we include every commitment in our permanent state. */
  state_commits = sr_state_get_commits();
  DIGEST256MAP_FOREACH(state_commits, key,
                       const sr_commit_t *, commit) {
    char *line = get_vote_line_from_commit(commit);
    smartlist_add(chunks, line);
    log_warn(LD_DIR, "[SR] \t Commit: %s", line);
  } DIGEST256MAP_FOREACH_END;

  /* Add the SRV value(s) if any. */
  {
    char *srv_lines = get_srv_ns_lines();
    smartlist_add(chunks, srv_lines);
  }

 end:
  vote_str = smartlist_join_strings(chunks, "", 0, NULL);
  SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
  smartlist_free(chunks);
  return vote_str;
}

/* Return 1 iff the two commits have the same commitment values. This
 * function does not care about reveal values. */
static int
commitments_are_the_same(const sr_commit_t *commit_one,
                         const sr_commit_t *commit_two)
{
  tor_assert(commit_one);
  tor_assert(commit_two);

  if (strcmp(commit_one->encoded_commit, commit_two->encoded_commit)) {
    return 0;
  }
  return 1;
}

/* We just received a commit from the vote of authority with
 * <b>identity_digest</b>. Return 1 if this commit is authorititative that
 * is, it belongs to the authority that voted it. Else return 0 if not. */
static int
commit_is_authoritative(const sr_commit_t *commit,
                        const ed25519_public_key_t *identity)
{
  tor_assert(commit);
  tor_assert(identity);

  return !fast_memcmp(&commit->auth_identity, identity,
                      sizeof(commit->auth_identity));
}

/* Decide if <b>commit</b> can be added to our state that is check if the
 * commit is authoritative. Return 1 if the commit should be added to our
 * state or 0 if not. If it's authoritative, the commit is flagged
 * accordingly. */
static int
should_keep_commit(sr_commit_t *commit,
                   const ed25519_public_key_t *voter_key)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(voter_key);

  log_warn(LD_DIR, "[SR] Considering whether we will keep commit.");

  /* For a commit to be considered, it needs to be authoritative (it should
   * be the voter's own commit). */
  if (!commit_is_authoritative(commit, voter_key)) {
    log_warn(LD_DIR, "[SR] \t Ignoring non-authoritative commit.");
    goto ignore;
  }

  /* Check if the authority that voted for <b>commit</b> has already posted a
     commit before. We use the RSA identity key to check from previous commits
     because an authority is allowed to rotate its ed25519 identity keys. */
  saved_commit = sr_state_get_commit_by_rsa(commit->rsa_identity_fpr);

  switch (sr_state_get_phase()) {
  case SR_PHASE_COMMIT:
    /* Already having a commit for an authority so ignore this one. */
    if (saved_commit) {
      log_warn(LD_DIR, "[SR] \t Ignoring known commit during commit phase.");
      goto ignore;
    }

    /* A commit with a reveal value is very wrong and constitute a bug. */
    if (commit_has_reveal_value(commit)) {
      /* XXX: should be LD_BUG at some point. */
      log_warn(LD_DIR, "[SR] Ignoring commit with reveal during commit phase");
      goto ignore;
    }
    break;
  case SR_PHASE_REVEAL:
    /* We are now in reveal phase. We keep a commit if and only if:

       - We have already seen a commit by this auth, AND
       - the saved commit has the same commitment value as this one, AND
       - the saved commit has no reveal information, AND
       - this commit does have reveal information, AND
       - the reveal & commit information are matching.

       If all the above are true, then we are interested in this new commit for
       its reveal information. */

    if (!saved_commit) {
      log_warn(LD_DIR, "[SR] \t Ignoring commit first seen in reveal phase.");
      goto ignore;
    }

    if (!commitments_are_the_same(commit, saved_commit)) {
      log_warn(LD_DIR, "[SR] \t Ignoring commit with wrong commitment info.");
      goto ignore;
    }

    if (commit_has_reveal_value(saved_commit)) {
      log_warn(LD_DIR, "[SR] \t Ignoring commit with known reveal info.");
      goto ignore;
    }

    if (!commit_has_reveal_value(commit)) {
      log_warn(LD_DIR, "[SR] \t Ignoring commit without reveal value.");
      goto ignore;
    }

    if (verify_commit_and_reveal(commit) < 0) {
      log_warn(LD_DIR, "[SR] \t Ignoring corrupted reveal info.");
      goto ignore;
    }
    break;
  default:
    tor_assert(0);
  }

  return 1;
 ignore:
  return 0;
}

/* Parse a list of arguments from a SRV value either from a vote, consensus
 * or from our disk state and return a newly allocated srv object. NULL is
 * returned on error.
 *
 * The arguments' order:
 *    status, value
 */
sr_srv_t *
sr_parse_srv(smartlist_t *args)
{
  char *value;
  sr_srv_t *srv = NULL;
  sr_srv_status_t status;

  tor_assert(args);

  /* First argument is the status. */
  status = sr_get_srv_status_from_str(smartlist_get(args, 0));
  if (status < 0) {
    goto end;
  }
  srv = tor_malloc_zero(sizeof(*srv));
  srv->status = status;

  /* Second and last argument is the shared random value it self. */
  value = smartlist_get(args, 1);
  memcpy(srv->value, value, sizeof(srv->value));

end:
  return srv;
}

/* Parse a list of arguments from a commitment either from a vote or from
 * our disk state and return a newly allocated commit object. NULL is
 * returned on error.
 *
 * The arguments' order matter very much:
 *  algname, ed25519 identity, RSA fingerprint, commit value[, reveal value]
 */
sr_commit_t *
sr_parse_commitment(smartlist_t *args)
{
  char *value;
  ed25519_public_key_t pubkey;
  digest_algorithm_t alg;
  const char *rsa_identity_fpr;
  sr_commit_t *commit = NULL;

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_DIR, "Commitment line algorithm %s is not recognized.",
             value);
    goto error;
  }
  /* Second arg is the authority ed25519 identity. */
  value = smartlist_get(args, 1);
  if (ed25519_public_from_base64(&pubkey, value) < 0) {
    log_warn(LD_DIR, "Commitment line identity is not recognized.");
    goto error;
  }

  /* Third argument is the RSA fingerprint of the auth */
  rsa_identity_fpr = smartlist_get(args, 2);

  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(&pubkey, rsa_identity_fpr);

  /* Fourth argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 3);
  if (commit_decode(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fifth argument is the revealed value. */
  value = smartlist_get(args, 4);
  if (value != NULL) {
    if (reveal_decode(value, commit) < 0) {
      goto error;
    }
  }

  return commit;
error:
  sr_commit_free(commit);
  return NULL;
}

/* Called when we have a valid vote and we are about to use it to compute a
 * consensus. The <b>commitments</b> is the list of commits from a single
 * vote coming from authority <b>voter_key</b>. We'll update our state with
 * that list. Once done, the list of commitments will be empty. */
void
sr_handle_received_commits(smartlist_t *commitments,
                           const ed25519_public_key_t *voter_key)
{
  tor_assert(voter_key);

  /* It's possible if our vote has seen _NO_ commits because it doesn't
   * contain any. */
  if (commitments == NULL) {
    return;
  }

  SMARTLIST_FOREACH_BEGIN(commitments, sr_commit_t *, commit) {
    /* We won't need the commit in this list anymore, kept or not. */
    SMARTLIST_DEL_CURRENT(commitments, commit);
    /* Check if this commit is valid and should be stored in our state. */
    if (!should_keep_commit(commit, voter_key)) {
      sr_commit_free(commit);
      continue;
    }
    /* Everything lines up: save this commit to state then! */
    save_commit_to_state(commit);
  } SMARTLIST_FOREACH_END(commit);
}

/* We are during commit phase and we found <b>commit</b> in a
 * vote. See if it contains any reveal values that we could use. */
static void
save_commit_during_reveal_phase(const sr_commit_t *commit)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);

  /* Get the commit from our state. */
  saved_commit = sr_state_get_commit_by_rsa(commit->rsa_identity_fpr);
  tor_assert(saved_commit);
  /* Safety net. They can not be different commitments at this point. */
  int same_commits = commitments_are_the_same(commit, saved_commit);
  tor_assert(same_commits);

  sr_state_set_commit_reveal(saved_commit, commit->encoded_reveal);
}

/* Save <b>commit</b> to our persistent state. Depending on the current phase,
 * different actions are taken. */
static void
save_commit_to_state(sr_commit_t *commit)
{
  sr_phase_t phase = sr_state_get_phase();

  switch (phase) {
  case SR_PHASE_COMMIT:
    /* During commit phase, just save any new authoritative commit */
    sr_state_add_commit(commit);
    break;
  case SR_PHASE_REVEAL:
    save_commit_during_reveal_phase(commit);
    break;
  default:
    tor_assert(0);
  }
}

static int
decide_num_participants(const or_options_t *options)
{
  int num_dirauth;

  tor_assert(options);

  if (options->NumSRParticipants) {
    return options->NumSRParticipants;
  }
  num_dirauth = get_n_authorities(V3_DIRINFO);
  /* If the params is not found, default value should always be the maximum
   * number of trusted authorities. Let's not take any chances. */
  return networkstatus_get_param(NULL, "NumSRParticipants", num_dirauth, 1,
                                 num_dirauth);
}

/* Return a heap-allocated string that should be put in the consensus and
 * contains the shared randomness values. It's the responsibility of the
 * caller to free the string. NULL is returned if no SRV(s) available. */
char *
sr_get_string_for_consensus(void)
{
  int num_participants, num_commits;
  char *srv_str;
  const digest256map_t *commits;
  const or_options_t *options = get_options();

  /* Not participating, avoid returning anything. */
  if (!options->VoteSharedRandom) {
    log_warn(LD_DIR, "[SR] Support disabled (VoteSharedRandom %d)",
             options->VoteSharedRandom);
    goto end;
  }

  /* XXX: Must validate the number of participant consensus params. */
  commits = sr_state_get_commits();
  num_commits = digest256map_size(commits);
  num_participants = decide_num_participants(options);
  if (num_participants < num_commits) {
    log_warn(LD_DIR, "[SR] Not enough participants. Need %d, have %d",
             num_participants, num_commits);
    goto end;
  }
  log_warn(LD_DIR, "[SR] We have enough participants! Needed %d, have %d",
           num_participants, num_commits);

  srv_str = get_srv_ns_lines();
  if (strlen(srv_str) == 0) {
    tor_free(srv_str);
    goto end;
  }

  /* XXX: debugging. */
  log_warn(LD_DIR, "[SR] Shared random line(s) put in the consensus:");
  log_warn(LD_DIR, "[SR] \t %s", srv_str);
  return srv_str;
 end:
  return NULL;
}

/* Prepare the shared random state we are going to be using for the upcoming
 * voting period at <b>valid_after</b>. This function should be called once
 * at the beginning of each new voting period. */
void
sr_prepare_new_voting_period(time_t valid_after)
{
  /* Make sure our state is coherent for the next voting period. */
  sr_state_update(valid_after);
}
