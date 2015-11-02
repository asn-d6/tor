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
 * This file implements the dirauth-only commit-and-reveal protocol specified by
 * proposal #250. The protocol has two phases (sr_phase_t): the commitment phase
 * and the reveal phase.
 *
 * The rough procedure is:
 *
 *      1) In the beginning of the commitment phase, dirauths generate a
 *         commitment/reveal value for the current protocol run (see
 *         new_protocol_run()).
 *
 *      2) Dirauths publish commitment/reveal values in their votes depending on
 *         the current phase (see sr_get_commit_string_for_vote()).
 *
 *      3) After all votes have been received, dirauths decide which
 *         commitments/reveals to keep (see sr_decide_post_voting()).
 *
 *      4) In the end of the reveal phase, dirauths compute the random value of
 *         the day using the active reveal values (see sr_compute_srv()).
 *
 * To better support rebooting authorities we save the current state of the
 * shared random protocol in disk so that authorities can resume on the protocol
 * if they have to reboot.
 *
 **/

#define SHARED_RANDOM_PRIVATE

#include "shared-random.h"
#include "config.h"
#include "confparse.h"
#include "routerkeys.h"
#include "router.h"
#include "routerlist.h"
#include "shared-random-state.h"

/* String representation of a shared random value status. */
static const char *srv_status_str[] = { "fresh", "non-fresh" };

/* Commits from an authority vote. This is indexed by authority shared
 * random key and an entry is a digest map of valid commit (since commit in
 * a vote MUST be unique). */
static digest256map_t *voted_commits;

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
commit_new(const ed25519_public_key_t *identity)
{
  sr_commit_t *commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  tor_assert(identity);
  memcpy(&commit->auth_identity, identity, sizeof(commit->auth_identity));
  /* This call can't fail. */
  ed25519_public_to_base64(commit->auth_fingerprint, identity);
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

  log_warn(LD_DIR, "[SR] \t Commit for %s", commit->auth_fingerprint);

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

/* Allocate a new conflict commit object. If <b>identity</b> is given, it's
 * copied into the object. The commits pointer <b>c1</b> and <b>c2</b> are
 * set in the object as is, they are NOT dup. This means that the caller
 * MUST not free the commits and should consider the conflict object having
 * a reference on them. This never returns NULL. */
static sr_conflict_commit_t *
conflict_commit_new(sr_commit_t *c1, sr_commit_t *c2)
{
  sr_conflict_commit_t *conflict = tor_malloc_zero(sizeof(*conflict));

  tor_assert(c1);
  tor_assert(c2);

  /* This is should NEVER happen else code flow issue. */
  int key_are_equal = tor_memeq(&c1->auth_identity, &c2->auth_identity,
                                sizeof(c1->auth_identity));
  tor_assert(key_are_equal);
  conflict->commit1 = c1;
  conflict->commit2 = c2;
  return conflict;
}

/* Free a conflict commit object. */
void
sr_conflict_commit_free(sr_conflict_commit_t *conflict)
{
  if (conflict == NULL) {
    return;
  }
  sr_commit_free(conflict->commit1);
  sr_commit_free(conflict->commit2);
  tor_free(conflict);
}

/* Free all commit object in the given list. */
static void
voted_commits_free(digest256map_t *commits)
{
  tor_assert(commits);
  DIGEST256MAP_FOREACH(commits, key, sr_commit_t *, c) {
    sr_commit_free(c);
  } DIGEST256MAP_FOREACH_END;
}

/* Helper: deallocate a list of commit object that comes from the
 * voted_commits map. (Used with digest256map_free(), which requires a
 * function pointer whose argument is void *). */
static void
voted_commits_free_(void *p)
{
  voted_commits_free(p);
}

/* Make sure that the commitment and reveal information in <b>commit</b>
 * match. If they match return 0, return -1 otherwise. This function MUST be
 * used everytime we receive a new reveal value. */
STATIC int
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

/* We just received <b>conflict</b> in a vote. Make sure that it's valid by
 * verifying its commit if they are from the same authority and if the
 * signature matches for them. */
static int
verify_received_conflict(const sr_conflict_commit_t *conflict)
{
  tor_assert(conflict);

  if (!sr_verify_conflict(conflict)) {
    goto invalid;
  }

  return 0;
 invalid:
  return -1;
}

/* We just received <b>commit</b> in a vote. Make sure that it's conforming
 * to the current protocol phase. Verify its signature and timestamp. */
static int
verify_received_commit(const sr_commit_t *commit)
{
  int have_reveal;

  tor_assert(commit);

  /* Verify commit signature. */
  if (!sr_verify_commit_sig(commit)) {
    goto invalid;
  }

  have_reveal = !tor_mem_is_zero(commit->encoded_reveal,
                                 sizeof(commit->encoded_reveal));
  switch (sr_state_get_phase()) {
  case SR_PHASE_COMMIT:
    /* During commit phase, we shouldn't get a reveal value and if so this
     * is considered as a malformed commit thus invalid. */
    if (have_reveal) {
      log_warn(LD_DIR, "[SR] Found commit with reveal value during commit phase.");
      goto invalid;
    }
    break;
  case SR_PHASE_REVEAL:
    /* We do have a reveal so let's verify it. */
    if (have_reveal) {
      if(verify_commit_and_reveal(commit) < 0) {
        goto invalid;
      }
    }
    break;
  default:
    goto invalid;
  }

  log_warn(LD_DIR, "[SR] \t Commit for %s has been verified successfully!",
           commit->auth_fingerprint);
  return 0;
 invalid:
  return -1;
}

/* Parse the encoded commit. The format is:
 *    base64-encode( H(REVEAL) || TIMESTAMP || SIGNATURE)
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
  char b64_decoded[SR_COMMIT_LEN + 1];

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
                              encoded, SR_COMMIT_BASE64_LEN);
  if (decoded_len < 0) {
    log_warn(LD_DIR, "[SR] Commitment can't be decoded.");
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
  offset += sizeof(uint64_t);
  /* Finally is the signature of the commit. */
  memcpy(&commit->commit_signature.sig, b64_decoded + offset,
         sizeof(commit->commit_signature.sig));
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
                              encoded, SR_REVEAL_BASE64_LEN);
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
  memcpy(commit->random_number, b64_decoded + sizeof(uint64_t),
         sizeof(commit->random_number));
  /* Also copy the whole message to use during verification */
  strncpy(commit->encoded_reveal, encoded, sizeof(commit->encoded_reveal));

  log_warn(LD_DIR, "[SR] Parsed reveal from %s", commit->auth_fingerprint);
  commit_log(commit);

  return 0;

 error:
  return -1;
}

/* Parse a Conflict line from our disk state and return a newly allocated
 * conflict commit object. NULL is returned on error. */
sr_conflict_commit_t *
sr_parse_conflict_line(smartlist_t *args)
{
  char *value;
  ed25519_public_key_t identity;
  sr_commit_t *commit1 = NULL, *commit2 = NULL;
  sr_conflict_commit_t *conflict = NULL;

  /* First argument is the authority identity. */
  value = smartlist_get(args, 0);
  if (ed25519_public_from_base64(&identity, value) < 0) {
    log_warn(LD_DIR, "Conflict line identity is not recognized.");
    goto error;
  }
  /* Second argument is the first commit value base64-encoded. */
  commit1 = commit_new(&identity);
  value = smartlist_get(args, 1);
  if (commit_decode(value, commit1) < 0) {
    goto error;
  }
  /* Third argument is the second commit value base64-encoded. */
  commit2 = commit_new(&identity);
  value = smartlist_get(args, 2);
  if (commit_decode(value, commit2) < 0) {
    goto error;
  }
  /* Everything is parsing correctly, allocate object and return it. */
  conflict = conflict_commit_new(commit1, commit2);
  return conflict;
error:
  sr_conflict_commit_free(conflict);
  sr_commit_free(commit1);
  sr_commit_free(commit2);
  return NULL;
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
  offset += sizeof(uint64_t);
  memcpy(buf + offset, commit->random_number,
         sizeof(commit->random_number));
  /* Let's clean the buffer and then encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Encode the given commit object to dst which is a buffer large enough to
 * put the base64-encoded commit. The format is as follow:
 *     COMMIT = base64-encode( H(REVEAL) || TIMESTAMP || SIGNATURE )
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
  /* The timestamp is next. */
  set_uint64(buf + offset, tor_htonll((uint64_t) commit->commit_ts));
  offset += sizeof(uint64_t);
  /* Finally, the signature. */
  memcpy(buf + offset, commit->commit_signature.sig,
         sizeof(commit->commit_signature.sig));
  /* Clean the buffer and then encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Cleanup both our global state and disk state. */
static void
sr_cleanup(void)
{
  digest256map_free(voted_commits, voted_commits_free_);
  sr_state_free();
}

/* Initialize shared random subsystem. This MUST be call early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  voted_commits = digest256map_new();
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
sr_generate_our_commitment(time_t timestamp)
{
  sr_commit_t *commit;
  const ed25519_keypair_t *signing_keypair;

  /* Get our shared random keypair. */
  signing_keypair = get_shared_random_keypair();
  tor_assert(signing_keypair);

  /* New commit with our identity key. */
  commit = commit_new(&signing_keypair->pubkey);

  /* Generate the reveal random value */
  if (crypto_rand((char *) commit->random_number,
                  sizeof(commit->random_number)) < 0) {
    log_err(LD_REND, "[SR] Unable to generate reveal random value!");
    goto error;
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

  { /* Now create the commit signature */
    uint8_t sig_msg[SR_COMMIT_SIG_BODY_LEN];
    memset(sig_msg, 0, sizeof(sig_msg));

    /* Signature message format: H(REVEAL) || TIMESTAMP */
    memcpy(sig_msg, commit->hashed_reveal, sizeof(commit->hashed_reveal));
    set_uint64(sig_msg + sizeof(commit->hashed_reveal),
               tor_htonll((uint64_t) commit->commit_ts));

    if (ed25519_sign(&commit->commit_signature, sig_msg, sizeof(sig_msg),
                     signing_keypair) < 0) {
      log_warn(LD_BUG, "[SR] Can't sign commitment!");
      goto error;
    }
  }

  /* Now get the base64 blob that corresponds to our commit. */
  if (commit_encode(commit, commit->encoded_commit,
                    sizeof(commit->encoded_commit)) < 0) {
    log_err(LD_REND, "[SR] Unable to encode the commit value!");
    goto error;
  }

  /* This is _our_ commit so it's authoritative. */
  commit->is_authoritative = 1;

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
  offset += sizeof(uint8_t);
  set_uint8(msg + offset, SR_PROTO_VERSION);
  offset += sizeof(uint8_t);
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
  /* No reveal values means that we are booting up in the reveal phase thus
   * we shouldn't try to compute a shared random value. */
  if (reveal_num == 0) {
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

/* Given <b>conflict</b> give the line that we should place in our votes.
 * It's the responsibility of the caller to free the string. */
static char *
get_vote_line_from_conflict(const sr_conflict_commit_t *conflict)
{
  char *line = NULL;
  static const char *conflict_str_key = "shared-rand-conflict";

  tor_assert(conflict);

  tor_asprintf(&line, "%s %s %s %s\n",
               conflict_str_key,
               conflict->commit1->auth_fingerprint,
               conflict->commit1->encoded_commit,
               conflict->commit2->encoded_commit);
  return line;
}

/* Return a smartlist for which each element is the SRV line that should be
 * put in a vote or consensus. Caller must free the string elements in the
 * list once done with it. */
static smartlist_t *
get_srv_vote_line(void)
{
  char *srv_line = NULL;
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
  return lines;
}

/* Return a heap-allocated string that should be put in the votes and
 * contains the shared randomness information for this phase. It's the
 * responsibility of the caller to free the string. */
char *
sr_get_commit_string_for_vote(void)
{
  char *vote_str = NULL;
  digest256map_t *state_commits, *state_conflicts;
  smartlist_t *chunks = smartlist_new();

  log_warn(LD_DIR, "[SR] Sending out vote string:");

  /* In our vote we include every commitment in our permanent state. */
  state_commits = sr_state_get_commits();
  DIGEST256MAP_FOREACH(state_commits, key,
                       const sr_commit_t *, commit) {
    char *line = get_vote_line_from_commit(commit);
    smartlist_add(chunks, line);
    log_warn(LD_DIR, "[SR] \t Commit: %s", line);
  } DIGEST256MAP_FOREACH_END;

  /* Add conflict(s) to our vote. */
  state_conflicts = sr_state_get_conflicts();
  DIGEST256MAP_FOREACH(state_conflicts, key,
                       const sr_conflict_commit_t *, conflict) {
    char *line = get_vote_line_from_conflict(conflict);
    smartlist_add(chunks, line);
    log_warn(LD_DIR, "[SR] \t Conflict: %s", line);
  } DIGEST256MAP_FOREACH_END;

  /* Add the SRV values to the string. */
  {
    smartlist_t *srv_lines = get_srv_vote_line();
    smartlist_add_all(chunks, srv_lines);
    smartlist_free(srv_lines);
  }

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

/* Add a commit that has just been seen in <b>voter_key<b/>'s vote to our
 * voted list. If an entry for the voter is not found, one is created. If
 * there is already a commit from the same authority key in the voter's
 * list, create a conflict since this is NOT allowed. */
static void
add_voted_commit(sr_commit_t *commit, const ed25519_public_key_t *voter_key)
{
  sr_commit_t *saved_commit;
  digest256map_t *entry;

  tor_assert(commit);
  tor_assert(voter_key);

  /* Make sure we have an entry for the voter key and if not create one.
   * We'll populare the entry after verification. */
  entry = digest256map_get(voted_commits, voter_key->pubkey);
  if (entry == NULL) {
    entry = digest256map_new();
    digest256map_set(voted_commits, voter_key->pubkey, entry);
  }

  /* An authority is allowed to commit only one value thus each vote MUST
   * only have one commit per authority. */
  saved_commit = digest256map_get(entry, commit->auth_identity.pubkey);
  if (saved_commit != NULL) {
    /* Since commit are carried on at each voting period, let's make sure we
     * have the same commit and if not, add a conflict. */
    if (!commitments_are_the_same(commit, saved_commit)) {
      /* Remove from list since the conflict object needs ownership. */
      digest256map_remove(entry, saved_commit->auth_identity.pubkey);
      /* Let's create a conflict here in order to ignore this mis-behaving
       * authority from now one. */
      sr_conflict_commit_t *conflict =
        conflict_commit_new(commit, saved_commit);
      sr_state_add_conflict(conflict);
    }
  } else {
    /* Unique entry for now, add it indexed by the commit authority key. */
    digest256map_set(entry, commit->auth_identity.pubkey, commit);
  }
}

/* Parse a Commitment line from our disk state and return a newly allocated
 * commit object. NULL is returned on error. */
sr_commit_t *
sr_parse_commitment_line(smartlist_t *args)
{
  char *value;
  ed25519_public_key_t pubkey;
  digest_algorithm_t alg;
  sr_commit_t *commit = NULL;

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_DIR, "Commitment line algorithm %s is not recognized.",
             value);
    goto error;
  }
  /* Second arg is the authority identity. */
  value = smartlist_get(args, 1);
  if (ed25519_public_from_base64(&pubkey, value) < 0) {
    log_warn(LD_DIR, "Commitment line identity is not recognized.");
    goto error;
  }
  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(&pubkey);

  /* Third argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 2);
  if (commit_decode(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fourth argument is the revealed value. */
  value = smartlist_get(args, 3);
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

/* Given all the commitment information from a commitment line in a vote,
 * parse the line, validate it and add it to the voted commits map if it's
 * valid so we can process all commits in post voting stage. */
void
sr_handle_received_commitment(const char *commit_pubkey, const char *hash_alg,
                              const char *commitment, const char *reveal,
                              const ed25519_public_key_t *voter_key)
{
  sr_commit_t *commit;
  smartlist_t *args;

  tor_assert(commit_pubkey);
  tor_assert(hash_alg);
  tor_assert(commitment);

  /* XXX: debugging */
  {
    char voter_fp[ED25519_BASE64_LEN + 1];
    ed25519_public_to_base64(voter_fp, voter_key);
    log_warn(LD_DIR, "[SR] Received commit from %s", voter_fp);
    log_warn(LD_DIR, "[SR] \t for: %s", commit_pubkey);
    log_warn(LD_DIR, "[SR] \t C: %s", commitment);
    log_warn(LD_DIR, "[SR] \t R: %s", reveal);
  }

  /* Build a list of arguments that have the same order as the Commitment
   * line in the state. With that, we can parse it using the same function
   * that the state uses. Line format is as follow:
   *    "shared-rand-commitment" SP algname SP identity SP
   *                             commitment-value [SP revealed-value] NL
   */
  args = smartlist_new();
  smartlist_add(args, (char *) hash_alg);
  smartlist_add(args, (char *) commit_pubkey);
  smartlist_add(args, (char *) commitment);
  if (reveal != NULL) {
    smartlist_add(args, (char *) reveal);
  }
  /* Parse our arguments to get a commit that we'll then verify. */
  commit = sr_parse_commitment_line(args);
  if (commit == NULL) {
    goto end;
  }
  /* We now have a commit object that has been fully populated by our vote
   * data. Now we'll validate it. This function will make sure also to
   * validate the reveal value if one is present. */
  if (verify_received_commit(commit) < 0) {
    /* XXX: This means we got a INVALID commit from an authority (either
     * hers or someone else). Should we create a conflict for the authority
     * that sent us this commit (voter_key) so we ignore it for the rest of
     * the voting period? */
    sr_commit_free(commit);
    commit = NULL;
    goto end;
  }

  /* Add the commit to our voted commit list so we can process them once we
   * decide our state in the post voting stage. */
  add_voted_commit(commit, voter_key);

end:
  smartlist_free(args);
}

/* Given all the conflict information from a conflict line in a vote, parse
 * the line, validate it and add it to our state if valid. */
void
sr_handle_received_conflict(const char *auth_identity,
                            const char *encoded_commit1,
                            const char *encoded_commit2,
                            const ed25519_public_key_t *voter_key)
{
  sr_conflict_commit_t *conflict;
  smartlist_t *args;

  tor_assert(auth_identity);
  tor_assert(encoded_commit1);
  tor_assert(encoded_commit2);
  tor_assert(voter_key);

  /* XXX: debugging */
  {
    char voter_fp[ED25519_BASE64_LEN + 1];
    ed25519_public_to_base64(voter_fp, voter_key);
    log_warn(LD_DIR, "[SR] Received conflict from %s", voter_fp);
    log_warn(LD_DIR, "[SR] \t for: %s", auth_identity);
  }

  /* Build a list of arguments that have the same order as the Conflict
   * line in the state. With that, we can parse it using the same function
   * that the state uses. Line format is as follow:
   *    "shared-rand-conflict" SP identity SP commit1 SP commit2 NL
   */
  args = smartlist_new();
  smartlist_add(args, (char *) auth_identity);
  smartlist_add(args, (char *) encoded_commit1);
  smartlist_add(args, (char *) encoded_commit2);
  /* Parse our arguments to get a commit that we'll then verify. */
  conflict = sr_parse_conflict_line(args);
  if (conflict == NULL) {
    goto end;
  }
  /* We now have a conflict object that has been fully populated by our vote
   * data. Now we'll validate it. */
  if (verify_received_conflict(conflict) < 0) {
    /* XXX: This means we got a INVALID conflict from an authority (either
     * hers or someone else). Should we create a conflict for the authority
     * so we ignore it for the rest of the voting period? */
    sr_conflict_commit_free(conflict);
    goto end;
  }
  /* Ok conflict is good and verified so add it to our state. */
  sr_state_add_conflict(conflict);

end:
  smartlist_free(args);
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

  /* Let's avoid some useless work here. Protect those CPU cycles! */
  if (commit->is_authoritative) {
    return 1;
  }
  return !fast_memcmp(&commit->auth_identity, identity,
                      sizeof(commit->auth_identity));
}

/* Decide if <b>commit</b> can be added to our state that is check if the commit
 * is authoritative. Return 1 if the commit should be added to our state or 0 if
 * not. */
static int
should_keep_commitment(sr_commit_t *commit,
                       const ed25519_public_key_t *voter_key)
{
  tor_assert(commit);
  tor_assert(voter_key);

  /* For a commit to be added to our state, we need it to be authoritative, that
   * is it's the voter's commit. */
  commit->is_authoritative = commit_is_authoritative(commit, voter_key);

  return commit->is_authoritative;
}

/* We are during commit phase and we found <b>commit</b> in a vote of
 * <b>voter_fingerprint</b>. All the other received votes are found in
 * <b>votes</b>. Decide whether we should keep this commit, issue a conflict
 * line, or ignore it. */
static int
decide_commit_during_commit_phase(sr_commit_t *commit,
                                  const ed25519_public_key_t *voter_key)
{
  /* Indicate if we kept the commit for our state or not. */
  int commit_kept = 0;
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(voter_key);

  log_warn(LD_DIR, "[SR] \t Deciding commit %s by %s",
           commit->encoded_commit, commit->auth_fingerprint);

  /* Query our state to know if we already have this commit saved. If so,
   * use the saved commit else use the new one. */
  saved_commit = sr_state_get_commit(&commit->auth_identity);
  if (saved_commit != NULL) {
    /* They can not be different commits at this point since we've
     * already processed all conflicts. */
    int same_commits = commitments_are_the_same(commit, saved_commit);
    tor_assert(same_commits);
    /* From now on, uses the commit found in our state. */
    commit = saved_commit;
  }

  /* Decide the state of the commit which will tell us if we can add it to
   * our state. This also updates the commit object. */
  if (should_keep_commitment(commit, voter_key)) {
    /* Let's not add a commit that we already have. */
    if (saved_commit == NULL) {
      sr_state_add_commit(commit);
      commit_kept = 1;
    }
  } else {
    char voter_fp[ED25519_BASE64_LEN + 1];
    ed25519_public_to_base64(voter_fp, voter_key);
    log_warn(LD_DIR, "[SR] Commit of authority %s received from %s "
                     "is not authoritative. Ignoring.",
             commit->auth_fingerprint, voter_fp);
  }
  return commit_kept;
}

/* We are during commit phase and we found <b>commit</b> in a
 * vote. See if it contains any reveal values that we could use. */
static void
decide_commit_during_reveal_phase(const sr_commit_t *commit)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);

  int have_reveal = !tor_mem_is_zero(commit->encoded_reveal,
                                     sizeof(commit->encoded_reveal));
  log_warn(LD_DIR, "[SR] \t Commit %s (%s) by %s",
           commit->encoded_commit,
           have_reveal ? commit->encoded_reveal : "NOREVEAL",
           commit->auth_fingerprint);

  /* If the received commit contains no reveal value, we are not interested
   * in it so ignore. */
  if (!have_reveal) {
    return;
  }

  /* Get the commit from our state. If it's not found, it's possible that we
   * didn't get a commit from the commit phase but we now see the reveal
   * from someone else. In this case, we ignore it since we didn't rule that
   * this commit should be kept. */
  saved_commit = sr_state_get_commit(&commit->auth_identity);
  if (saved_commit == NULL) {
    return;
  }
  /* They can not be different commits at this point since we've
   * already processed all conflicts. */
  int same_commits = commitments_are_the_same(commit, saved_commit);
  tor_assert(same_commits);

  /* If we already have a commitment by this authority, and our saved
   * commit doesn't have a reveal value, add it. */
  log_warn(LD_DIR, "[SR] \t \t Ah, learned reveal %s for commit %s",
           commit->encoded_reveal, commit->encoded_commit);
  strncpy(saved_commit->encoded_reveal, commit->encoded_reveal,
         sizeof(saved_commit->encoded_reveal));
}

/* Go over the every voted commit and check if we already have a commit from
 * the same authority but with a different value in our state and if so add
 * the conflict to the state.  */
static void
decide_conflict_from_votes(void)
{
  DIGEST256MAP_FOREACH(voted_commits, key, digest256map_t *, commits) {
    /* For each voter, we'll make sure we don't have any conflicts for the
     * vote they sent us. */
    DIGEST256MAP_FOREACH_MODIFY(commits, c_key, sr_commit_t *, commit) {
      sr_commit_t *saved_commit =
        sr_state_get_commit(&commit->auth_identity);
      if (saved_commit == NULL) {
        /* No conflict since we do not have it in our state. Ignore. */
        continue;
      }
      /* Is it a different commit from our state? If yes, add a conflict to
       * the state. */
      if (!commitments_are_the_same(commit, saved_commit)) {
        sr_conflict_commit_t *conflict = conflict_commit_new(commit,
                                                             saved_commit);
        sr_state_add_conflict(conflict);
        /* We must remove those commits since they are now owned by the
         * conflict object. */
        MAP_DEL_CURRENT(c_key);
        sr_state_remove_commit(&saved_commit->auth_identity);
      }
    } DIGEST256MAP_FOREACH_END;
  } DIGEST256MAP_FOREACH_END;
}

/* For all vote in <b>votes</b>, decide if the commitments should be ignored
 * or added/updated to our state. Depending on the phase here, different
 * actions are taken. */
static void
decide_commit_from_votes(sr_phase_t phase)
{
  tor_assert(phase == SR_PHASE_COMMIT || phase == SR_PHASE_REVEAL);

  DIGEST256MAP_FOREACH(voted_commits, key, digest256map_t *, commits) {
    /* Build our voter key to ease our life a bit. */
    ed25519_public_key_t voter_key;
    memcpy(voter_key.pubkey, key, sizeof(voter_key.pubkey));

    /* IMPORTANT: Ignore authority vote if we have a conflict for it. */
    if (sr_state_get_conflict(&voter_key)) {
      continue;
    }

    /* Go over all commitments and depending on the phase decide what to do
     * with them that is keeping or updating them based on the votes. */
    DIGEST256MAP_FOREACH_MODIFY(commits, c_key, sr_commit_t *, commit) {
      switch (phase) {
      case SR_PHASE_COMMIT:
        if (decide_commit_during_commit_phase(commit, &voter_key)) {
          /* Commit has been added to our state so remove it from this map
           * so we transfer ownership to the state. */
          MAP_DEL_CURRENT(c_key);
        }
        break;
      case SR_PHASE_REVEAL:
        decide_commit_during_reveal_phase(commit);
        break;
      default:
        tor_assert(0);
      }
    } DIGEST256MAP_FOREACH_END;
  } DIGEST256MAP_FOREACH_END;
}

/* Return 1 iff the conflict commits can be verified using the commit
 * authority fingerprint. Else return 0. */
int
sr_verify_conflict(const sr_conflict_commit_t *conflict)
{
  tor_assert(conflict);

  return sr_verify_commit_sig(conflict->commit1) &
    sr_verify_commit_sig(conflict->commit2);
}

/* Return 1 iff the commit signature can be verified using the commit
 * authority fingerprint. Else return 0. */
int
sr_verify_commit_sig(const sr_commit_t *commit)
{
  uint8_t sig_msg[SR_COMMIT_SIG_BODY_LEN];

  tor_assert(commit);

  /* Let's verify the signature of the commitment. Format is:
   *    H(REVEAL) || TIMESTAMP */
  memcpy(sig_msg, commit->hashed_reveal, sizeof(commit->hashed_reveal));
  set_uint64(sig_msg + sizeof(commit->hashed_reveal),
             tor_htonll((uint64_t) commit->commit_ts));
  if (ed25519_checksig(&commit->commit_signature, sig_msg,
                       SR_COMMIT_SIG_BODY_LEN, &commit->auth_identity) != 0) {
    log_warn(LD_DIR, "[SR] Commit signature from %s is invalid!",
             commit->auth_fingerprint);
    goto invalid;
  }
  return 1;
 invalid:
  return 0;
}

/* Return a heap-allocated string that should be put in the consensus and
 * contains the shared randomness values. It's the responsibility of the
 * caller to free the string. */
char *
sr_get_consensus_srv_string(void)
{
  char *srv_str;
  smartlist_t *srv_lines = get_srv_vote_line();

  if (!srv_lines) {
    return NULL;
  }

  srv_str = smartlist_join_strings(srv_lines, "", 0, NULL);
  SMARTLIST_FOREACH(srv_lines, char *, s, tor_free(s));
  smartlist_free(srv_lines);
  /* XXX: debugging. */
  log_warn(LD_DIR, "[SR] Shared random value for the consensus:");
  log_warn(LD_DIR, "[SR] \t %s", srv_str);
  return srv_str;
}

/* This is called in the end of each voting round. Decide which
 * commitments/reveals to keep and write them to perm state. */
void
sr_decide_post_voting(void)
{
  log_warn(LD_DIR, "[SR] Deciding stage post voting.");

  /* First step is to find if we have any conflicts and if so add them to our
   * state. This is important because after that we will decide if we keep the
   * commitments as authoritative from which we MUST exclude conflicts. */
  decide_conflict_from_votes();

   /* Then we decide which commit to keep in our state considering that all
    * conflicts have been found previously. */
  decide_commit_from_votes(sr_state_get_phase());

  /* For last, we've just processed all of the voted commits so cleanup the
   * map since we are post voting and we won't need them anymore. It also
   * need to be cleaned up before the next voting period starts. */
  digest256map_free(voted_commits, voted_commits_free_);
  voted_commits = digest256map_new();

  log_warn(LD_DIR, "[SR] State decided!");
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
