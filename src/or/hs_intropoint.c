/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_intropoint.c
 * \brief Implement next generation introductions point functionality
 **/

#define HS_INTROPOINT_PRIVATE

#include "or.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "relay.h"
#include "rendmid.h"

#include "hs_establish_intro.h"
#include "hs_intropoint.h"

/* XXX also exists in hs_service.c . move to hs_common.c or sth */
#define ESTABLISH_INTRO_SIG_PREFIX "Tor establish-intro cell v1"

/** XXX remove */
static int
throw_circuit_error(or_circuit_t *circ, int reason)
{
  circuit_mark_for_close(TO_CIRCUIT(circ), reason);
  return -1;
}

/** Extract the AUTH_KEY from an ESTABLISH_INTRO <b>cell</b> and place it in
 *  <b>auth_key_out</b>. */
static void
get_auth_key_from_establish_intro_cell(ed25519_public_key_t *auth_key_out,
                                       hs_establish_intro_cell_t *cell)
{
  tor_assert(auth_key_out);

  uint8_t *key_array = hs_establish_intro_cell_getarray_auth_key(cell);
  tor_assert(key_array);

  memcpy(auth_key_out->pubkey, key_array, cell->auth_key_len);
}

/** <b>circ</b> just became an introduction point circuit to a hidden service
 *  with service auth key <b>auth_key</b>. Associate this circuit with that
 *  key, so that we can find it later. */
static int
associate_key_with_intro_circuit(or_circuit_t *circ,
                                 const ed25519_public_key_t *auth_key)
{
  char pk_digest[DIGEST_LEN];

  if (crypto_digest(pk_digest, (const char *)auth_key->pubkey, ED25519_PUBKEY_LEN)<0) {
    log_warn(LD_BUG, "Couldn't hash public key");
    return -1;
  }

  /* Make sure the key is not in use by another circuit; reject if so. */
  or_circuit_t *other_circ = circuit_get_intro_point((const uint8_t *)pk_digest);
  if (other_circ) {
    log_warn(LD_PROTOCOL, "Authentication key already in use");
    return -1;
  }

  /* Associate key with circuit and set circuit purpose */
  circuit_set_intro_point_digest(circ, (uint8_t *)pk_digest);

  return 0;
}

/** We received an ESTABLISH_INTRO cell in <b>cell</b>. Make sure its signature
 *  and MAC are correct given the <b>circuit_key_material</b>. */
STATIC int
verify_establish_intro_cell(hs_establish_intro_cell_t *cell,
                            const char *circuit_key_material,
                            size_t circuit_key_material_len)
{
  /* Make sure we understand the authentication version */
  if (cell->auth_key_type != 2) { /* XXX use AUTH_KEY_ED25519 */
    log_warn(LD_PROTOCOL,
             "Invalid ESTABLSH_INTRO AUTH_KEY_TYPE: must be in {0, 1, 2}");
    return -1;
  }

  /* Verify the MAC */
  const char *msg = (char*) cell->start_cell;
  const size_t auth_msg_len = (char*) (cell->end_mac_fields) - msg;
  char mac[SHA3_256_MAC_LEN];
  int mac_errors = crypto_hmac_sha3_256(mac,
                                        circuit_key_material,
                                        circuit_key_material_len,
                                        msg, auth_msg_len);
  if (mac_errors != 0) {
    log_warn(LD_BUG, "Error computing ESTABLISH_INTRO handshake_auth");
    return -1;
  }
  if (tor_memneq(mac, cell->handshake_sha3_256, SHA3_256_MAC_LEN)) {
    log_warn(LD_PROTOCOL, "ESTABLISH_INTRO handshake_auth not as expected");
    return -1;
  }

  /* Verify the sig */
  {
    ed25519_signature_t sig_struct;
    uint8_t *sig_array = hs_establish_intro_cell_getarray_sig(cell);
    memcpy(sig_struct.sig, sig_array, cell->siglen);

    ed25519_public_key_t auth_key;
    get_auth_key_from_establish_intro_cell(&auth_key, cell);

    /* XXX figure out how to incorporate the prefix: ask Nick! */
    const size_t sig_msg_len = (char*) (cell->end_sig_fields) - msg;
    int sig_mismatch = ed25519_checksig_prefixed(&sig_struct,
                                                 (uint8_t*) msg, sig_msg_len,
                                                 ESTABLISH_INTRO_SIG_PREFIX,
                                                 &auth_key);
    if (sig_mismatch) {
      log_warn(LD_PROTOCOL, "ESTABLISH_INTRO signature not as expected");
      return -1;
    }
  }

  return 0;
}

/** We just received an ESTABLISH_INTRO cell in circuit <b>circ</b> with
 *  payload in <b>request</b>. Handle it by becoming the intro point. Return 0
 *  if everything went well, or -1 if there were errors. */
static int
handle_establish_intro(or_circuit_t *circ, const uint8_t *request,
                   size_t request_len)
{
  int retval;
  hs_establish_intro_cell_t *parsed_cell = NULL;

  log_info(LD_REND,
           "Received an ESTABLISH_INTRO request on circuit %u",
           (unsigned) circ->p_circ_id);

  /* Basic sanity check on circuit purpose */
  /* XXX Should we also check circ->base_.n_chan like we do in
     rend_mid_establish_intro_legacy(). */
  if (circ->base_.purpose != CIRCUIT_PURPOSE_OR) {
    log_warn(LD_PROTOCOL,
             "Rejecting ESTABLISH_INTRO on non-OR or non-edge circuit.");
    goto err;
  }

  /* Parse the cell */
  ssize_t parsing_result = hs_establish_intro_cell_parse(&parsed_cell, request, request_len);
  /* XXX aren't error retvals negative here??? */
  if (parsing_result < 0) {
    log_warn(LD_PROTOCOL, "Rejecting %s ESTABLISH_INTRO cell.",
             parsing_result == -1 ? "invalid" : "truncated");
    goto err;
  }

  retval = verify_establish_intro_cell(parsed_cell,
                                       circ->rend_circ_nonce,
                                       sizeof(circ->rend_circ_nonce));
  if (retval < 0) {
    log_warn(LD_PROTOCOL, "Failed to verify ESTABLISH_INTRO cell.");
    goto err;
  }

  /* Associate auth key with circuit, and make it an intro circuit */
  /* XXX move after the INTRO_ESTABLISHED is sent */
  {
    ed25519_public_key_t auth_key;
    get_auth_key_from_establish_intro_cell(&auth_key, parsed_cell);

    /* Associate auth key with circ */
    if (associate_key_with_intro_circuit(circ, &auth_key) < 0) {
      log_warn(LD_BUG, "Trouble associating intro key with circuit");
      goto err;
    }

    /* Turn circ into an intro circ */
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_INTRO_POINT);
  }


  /* Notify the client that their intro point is established by sending an
     empty RELAY_COMMAND_INTRO_ESTABLISHED cell */
  char ack[1] = {0};
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_INTRO_ESTABLISHED,
                                   (const char *)ack, 1, NULL)<0) {
    log_warn(LD_BUG, "Couldn't send INTRO_ESTABLISHED cell.");
    goto err;
  }

  /* We are done! */
  return 0;

 err:
  tor_free(parsed_cell);
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TORPROTOCOL);
  return -1;
}

/* We just received an ESTABLISH_INTRO cell in <b>circ</b>. Figure out of it's
 * a legacy or a next gen cell, and pass it to the appropriate handler. */
int
hs_received_establish_intro(or_circuit_t *circ, const uint8_t *request,
                            size_t request_len)
{
  if (request_len < 1) { /* Defensive length check */
    log_warn(LD_PROTOCOL, "Incomplete ESTABLISH_INTRO cell.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  uint8_t first_byte = *request; /* XXX maybe turn into switch */
  if (first_byte == 0 || first_byte == 1) {
    return rend_mid_establish_intro_legacy(circ, request, request_len);
  } else if (first_byte == 2) {
    return handle_establish_intro(circ, request, request_len);
  } else {
    log_warn(LD_PROTOCOL, "Invalid AUTH_KEY_TYPE");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }
}
