/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_intropoint.c
 * \brief Implement next generation introductions point functionality
 **/

#include "or.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "relay.h"
#include "rendmid.h"

#include "hs_establish_intro.h"
#include "hs_intropoint.h"


static int
throw_circuit_error(or_circuit_t *circ, int reason)
{
  circuit_mark_for_close(TO_CIRCUIT(circ), reason);
  return -1;
}

/** We just received an ESTABLISH_INTRO cel in 'circ'. Handle it. */
static int
hs_handle_establish_intro(or_circuit_t *circ, const uint8_t *request,
                   size_t request_len)
{
  hs_establish_intro_cell_t *out = NULL;

  /* Basic sanity check on circuit purpose */
  /* XXX Should we also check circ->base_.n_chan like we do in
     rend_mid_establish_intro_legacy(). */
  if (circ->base_.purpose != CIRCUIT_PURPOSE_OR) {
    tor_free(out);
    log_warn(LD_PROTOCOL,
             "Rejecting ESTABLISH_INTRO on non-OR or non-edge circuit.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  /* Parse the cell */
  size_t parsing_result = hs_establish_intro_cell_parse(&out, request, request_len);
  /* XXX aren't error retvals negative here??? */
  if (parsing_result == 1) {
    // Input was invalid - log the rend_establish_intro_check result
    tor_free(out);
    log_warn(LD_PROTOCOL, "Rejecting invalid ESTABLISH_INTRO cell.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  } else if (parsing_result == 2) {
    // Input was possibly truncated
    tor_free(out);
    log_warn(LD_PROTOCOL, "Rejecting truncated ESTABLISH_INTRO cell.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  /* Make sure we understand the authentication version */
  if (out->auth_key_type != 2) {
    tor_free(out);
    log_warn(LD_PROTOCOL,
             "Invalid ESTABLSH_INTRO AUTH_KEY_TYPE: must be in {0, 1, 2}");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  /* Verify the MAC */
  const char *kh = circ->rend_circ_nonce;
  const size_t kh_len = DIGEST_LEN;
  const char *msg = (char*) out->start_cell;
  const size_t auth_msg_len = (char*) (out->end_mac_fields) - msg;
  char mac[SHA3_256_MAC_LEN];
  int mac_errors = crypto_hmac_sha3_256(mac, kh, kh_len, msg, auth_msg_len);
  if (mac_errors != 0) {
    tor_free(out);
    log_warn(LD_BUG, "Error computing ESTABLISH_INTRO handshake_auth");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }
  if (tor_memneq(mac, out->handshake_sha3_256, SHA3_256_MAC_LEN)) {
    tor_free(out);
    log_warn(LD_PROTOCOL, "ESTABLISH_INTRO handshake_auth not as expected");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  /* Verify the sig */
  ed25519_public_key_t key_struct;
  uint8_t *key_array = hs_establish_intro_cell_getarray_auth_key(out);
  memcpy(key_struct.pubkey, key_array, out->auth_key_len);
  {
    ed25519_signature_t sig_struct;
    uint8_t *sig_array = hs_establish_intro_cell_getarray_sig(out);
    memcpy(sig_struct.sig, sig_array, out->siglen);

    // Already copied to structs, can now free these
    tor_free(sig_array);
    tor_free(key_array);

    // TODO figure out how to incorporate the prefix: ask Nick!
    int sig_mismatch = ed25519_checksig(&sig_struct, (uint8_t*) msg, out->siglen, &key_struct);
    if (sig_mismatch) {
      tor_free(out);
      log_warn(LD_PROTOCOL, "ESTABLISH_INTRO signature not as expected");
      return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
    }
  }

  /* Associate auth key with circuit, and make it an intro circuit */
  {
    char pk_digest[DIGEST_LEN];
    if (crypto_digest(pk_digest, (const char *)key_struct.pubkey, ED25519_PUBKEY_LEN)<0) {
      tor_free(out);
      log_warn(LD_BUG, "Couldn't hash public key");
      return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
    }

    // Make sure the key is not in use by another circuit; reject if so.
    or_circuit_t *c = circuit_get_intro_point((const uint8_t *)pk_digest);
    if (c != NULL) {
      tor_free(out);
      log_warn(LD_PROTOCOL, "Authentication key already in use");
      return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
    }

    // Associate key with circuit and set circuit purpose
    circuit_set_intro_point_digest(circ, (uint8_t *)pk_digest);
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_INTRO_POINT);
  }

  /* Notify the client that their intro point is established by sending an
     empty RELAY_COMMAND_INTRO_ESTABLISHED cell */
  char ack[1] = {0};
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_INTRO_ESTABLISHED,
                                   (const char *)ack, 1, NULL)<0) {
    tor_free(out);
    log_warn(LD_BUG, "Couldn't send INTRO_ESTABLISHED cell.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  // We are done!
  return 0;
}

/* We just received an ESTABLISH_INTRO cell. Figure out of it's a legacy or a
   next generation cell, and pass it to the appropriate handler. */
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
    log_info(LD_REND,
        "Received a legacy ESTABLISH_INTRO request on circuit %u",
        (unsigned) circ->p_circ_id);
    return rend_mid_establish_intro_legacy(circ, request, request_len);
  } else if (first_byte == 2) {
    log_info(LD_REND,
        "Received an ESTABLISH_INTRO request on circuit %u",
        (unsigned) circ->p_circ_id);
    return hs_handle_establish_intro(circ, request, request_len);
  } else {
    log_warn(LD_PROTOCOL, "Invalid AUTH_KEY_TYPE");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }
}

