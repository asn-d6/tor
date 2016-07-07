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

static int
hs_establish_intro(or_circuit_t *circ, const uint8_t *request,
                   size_t request_len)
{
  hs_establish_intro_cell_t *out = NULL;

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

  // Input valid - commence validation
  if (out->auth_key_type != 2) {
    tor_free(out);
    log_warn(LD_PROTOCOL,
             "Invalid ESTABLSH_INTRO AUTH_KEY_TYPE: must be in {0, 1, 2}");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }
  // Since auth key is 2, auth key must be a ed25519_public_key_t
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

  ed25519_signature_t sig_struct;
  uint8_t *sig_array = hs_establish_intro_cell_getarray_sig(out);
  memcpy(sig_struct.sig, sig_array, out->siglen);

  ed25519_public_key_t key_struct;
  uint8_t *key_array = hs_establish_intro_cell_getarray_auth_key(out);
  memcpy(key_struct.pubkey, key_array, out->auth_key_len);

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

  // Cell has valid handshake and signature.
  // Make sure the circuit is neither an intro point nor a rend point.
  /* XXX Move this to top of function. Why here? */
  /* XXX Should we also check circ->base_.n_chan like we do in
     rend_mid_establish_intro_legacy(). */
  if (circ->base_.purpose != CIRCUIT_PURPOSE_OR) {
    tor_free(out);
    log_warn(LD_PROTOCOL,
             "Rejecting ESTABLISH_INTRO on non-OR or non-edge circuit.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  // For simplicity, don't save the key itself, only a 20-byte hash of the key.
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

  // Acknowledge the request.
  // Currently, just a single byte with a value of 0, since no extensions yet.
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

int
hs_received_establish_intro(or_circuit_t *circ, const uint8_t *request,
                            size_t request_len)
{
  if (request_len < 1) { /* Defensive length check */
    log_warn(LD_PROTOCOL, "Incomplete ESTABLISH_INTRO cell.");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }

  uint8_t first_byte = *request;
  if (first_byte == 0 || first_byte == 1) {
    log_info(LD_REND,
        "Received a legacy ESTABLISH_INTRO request on circuit %u",
        (unsigned) circ->p_circ_id);
    return rend_mid_establish_intro_legacy(circ, request, request_len);
  }
  else if (first_byte == 2) {
    log_info(LD_REND,
        "Received an ESTABLISH_INTRO request on circuit %u",
        (unsigned) circ->p_circ_id);
    return hs_establish_intro(circ, request, request_len);
  }
  else {
    log_warn(LD_PROTOCOL, "Invalid AUTH_KEY_TYPE");
    return throw_circuit_error(circ, END_CIRC_REASON_TORPROTOCOL);
  }
}

#if 0
void rend_service_intro_has_opened_p224(origin_circuit_t *circuit)
{
  // Ensure this is for establish intro
  tor_assert(circuit->base_.purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);
  rend_service_t *service = rend_service_get_by_pk_digest(
                circuit->rend_data->rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Unrecognized service ID.");
    return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_NOSUCHSERVICE);
  }

  /* XXX what is this? */
  if ((count_intro_point_circuits(service) -
       smartlist_len(service->expiring_nodes)) >
      service->n_intro_points_wanted) {
    /* Remove the intro point associated with this circuit, it's being
     * repurposed or closed thus cleanup memory. */
    rend_intro_point_t *intro = find_intro_point(circuit);
    if (intro != NULL) {
      smartlist_remove(service->intro_nodes, intro);
      rend_intro_point_free(intro);
    }

    if (get_options()->ExcludeNodes) {
      circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_NONE);
    } else {
      tor_assert(circuit->build_state->is_internal);
      circuit_change_purpose(TO_CIRCUIT(circuit), CIRCUIT_PURPOSE_C_GENERAL);
      {
        rend_data_t *rend_data = circuit->rend_data;
        circuit->rend_data = NULL;
        rend_data_free(rend_data);
      }
      {
        crypto_pk_t *intro_key = circuit->intro_key;
        circuit->intro_key = NULL;
        crypto_pk_free(intro_key);
      }

      circuit_has_opened(circuit);
    }
    return;
  }

  // Generate short-term keypair for use in ESTABLISH_INTRO
  ed25519_keypair_t key_struct;
  if(ed25519_keypair_generate(&key_struct, 0) < 0) {
      return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_NONE);
  }

  // Create empty establish_intro cell
  hs_establish_intro_cell_t *cell = rend_establish_intro_new();

  // Set AUTH_KEY_TYPE: 2 means ed25519
  hs_establish_intro_cell_set_auth_key_type(cell, 2);

  // Set AUTH_KEY_LEN field
  // Must also set byte-length of AUTH_KEY to match
  int auth_key_len = DIGEST256_LEN;
  hs_establish_intro_cell_set_auth_key_len(cell, auth_key_len);
  hs_establish_intro_cell_setlen_auth_key(cell, auth_key_len);

  // Set AUTH_KEY field
  uint8_t *auth_key_ptr = hs_establish_intro_cell_getarray_auth_key(cell);
  memcpy(auth_key_ptr, key_struct.pubkey.pubkey, auth_key_len);

  // No extensions for now
  hs_establish_intro_cell_set_n_extensions(cell, 0);
  hs_establish_intro_cell_setlen_extensions(cell, 0);

  // Generate handshake
  int handshake_len = SHA3_256_MAC_LEN;
  char mac[handshake_len];
  const char *kh = circuit->cpath->prev->rend_circ_nonce;
  const size_t kh_len = DIGEST_LEN;
  const char *msg = (char*) cell->start_cell;
  const size_t auth_msg_len = (char*) (cell->end_mac_fields) - msg;
  if (crypto_hmac_sha3_256(mac, kh, kh_len, msg, auth_msg_len)<0) {
    log_warn(LD_BUG, "Unable to generate handshake for ESTABLISH_INTRO cell.");
    return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_INTERNAL);
  }

  // Then add handshake to cell
  uint8_t *handshake_ptr =
    hs_establish_intro_cell_getarray_handshake_sha3_256(cell);
  memcpy(handshake_ptr, mac, handshake_len);

  // Set signature length
  int sig_len = ED25519_SIG_LEN;
  hs_establish_intro_cell_set_siglen(cell, sig_len);
  hs_establish_intro_cell_setlen_sig(cell, sig_len);

  // TODO figure out whether to prepend a string to sig or not
  ed25519_signature_t sig_struct;
  if (ed25519_sign(&sig_struct, (uint8_t*) msg, sig_len, &key_struct)) {
    log_warn(LD_BUG, "Unable to generate signature for ESTABLISH_INTRO cell.");
    return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_INTERNAL);
  }

  // And write the signature to the cell
  uint8_t *sig_ptr =
    hs_establish_intro_cell_getarray_sig(cell);
  memcpy(sig_ptr, sig_struct.sig, sig_len);

  // Finally, get a binary string and encode the cell
  int len = 1 + 1 + auth_key_len + 1 + handshake_len + 1 + sig_len;
  uint8_t buf[len];
  ssize_t bytes_used = hs_establish_intro_cell_encode(buf, len, cell);
  if (bytes_used < 0) {
    log_warn(LD_BUG, "Unable to generate valid ESTABLISH_INTRO cell");
    return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_INTERNAL);
  }

  // Double check for truncation
  tor_assert(bytes_used == len);

  // Free the cell object and send the message
  hs_establish_intro_cell_free(cell);
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circuit),
                                   RELAY_COMMAND_ESTABLISH_INTRO,
                                   (const char *)buf, len, circuit->cpath->prev)<0) {
    log_warn(LD_GENERAL, "Couldn't send introduction request");
    return circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_INTERNAL);
  }

  /* We've attempted to use this circuit */
  pathbias_count_use_attempt(circuit);
}

#endif
