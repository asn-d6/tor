/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation service functionality
 **/

#define HS_SERVICE_PRIVATE

#include "or.h"
#include "relay.h"
#include "rendservice.h"
#include "circuitlist.h"
#include "circpathbias.h"

#include "hs_service.h"
#include "hs_establish_intro.h"

/** XXX call chain:
    hs_service_intro_has_opened ->
    send_establish_intro_cell ->
    generate_establish_intro_cell / get_establish_intro_payload
*/

/* XXX DOCDOC */
static int
get_establish_intro_payload(uint8_t *buf, size_t buf_len,
                            const hs_establish_intro_cell_t *cell)
{
  if (buf_len < RELAY_PAYLOAD_SIZE) {
    return -1;
  }

  ssize_t bytes_used = hs_establish_intro_cell_encode(buf, buf_len, cell);
  if (bytes_used < 0) {
    return -1;
  }

  return 0;
}

/** XXX DOCDOCDOC cell is allocated on heap */
STATIC hs_establish_intro_cell_t *
generate_establish_intro_cell(const char *circuit_key_material,
                              size_t circuit_key_material_len)
{
  log_warn(LD_GENERAL,"Generating ESTABLISH_INTRO cell (key_material_len: %u)",
           (unsigned) circuit_key_material_len);

  // Generate short-term keypair for use in ESTABLISH_INTRO
  ed25519_keypair_t key_struct;
  if(ed25519_keypair_generate(&key_struct, 0) < 0) {
    return NULL;
  }

  hs_establish_intro_cell_t *cell = hs_establish_intro_cell_new();

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
  const char *msg = (char*) cell->start_cell;
  const size_t auth_msg_len = (char*) (cell->end_mac_fields) - msg;
  if (crypto_hmac_sha3_256(mac,
                           circuit_key_material, circuit_key_material_len,
                           msg, auth_msg_len)<0) {
    log_warn(LD_BUG, "Unable to generate handshake for ESTABLISH_INTRO cell.");
    return NULL; /* XXX nicer error handling */
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
    return NULL;
  }

  // And write the signature to the cell
  uint8_t *sig_ptr =
    hs_establish_intro_cell_getarray_sig(cell);
  memcpy(sig_ptr, sig_struct.sig, sig_len);

  return cell;
}

static int
send_establish_intro_cell(origin_circuit_t *circuit)
{
  int retval = -1;
  hs_establish_intro_cell_t *cell = NULL;

  /* Get a populated ESTABLISH_INTRO cell */
  {
    const char *circuit_key_material = circuit->cpath->prev->rend_circ_nonce;
    cell = generate_establish_intro_cell(circuit_key_material,
                                         sizeof(circuit_key_material));
    if (!cell) {
      log_warn(LD_GENERAL, "Couldn't generate ESTABLISH_INTRO cell!");
      return -1;
    }
  }

  /* Get payload of ESTABLISH_INTRO cell */
  const size_t buf_len = RELAY_PAYLOAD_SIZE;
  uint8_t buf[buf_len];
  retval = get_establish_intro_payload(buf, buf_len, cell);
  if (retval < 0) {
    log_warn(LD_GENERAL, "Couldn't get ESTABLISH_INTRO payload!");
    return -1;
  }

  // Free the cell object
  hs_establish_intro_cell_free(cell); /* XXX don't free here */

  /* Send the cell out there! */
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circuit), RELAY_COMMAND_ESTABLISH_INTRO,
                                   (const char *)buf, buf_len,
                                   circuit->cpath->prev) < 0) {
    log_warn(LD_GENERAL, "Couldn't send introduction request");
    return -1;
  }

  return 0;
}

/** Our circuit to the intro point just opened! Send out an ESTABLISH_INTRO cell. */
void
hs_service_intro_has_opened(origin_circuit_t *circuit)
{
  int retval = -1;

  /* Check that this circuit is a server-side intro circuit */
  tor_assert(circuit->base_.purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);

  /* LOL XXX */
#if 0
  rend_service_t *service = rend_service_get_by_pk_digest(
                circuit->rend_data->rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Unrecognized service ID.");
    circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_NOSUCHSERVICE);
    return;
  }

  /* Make sure this circuit is still needed. */
  /* XXX audit wtf */
  /* XXX See what other checks the old function was doing. */
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

    /* XXX lol wtf */
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
#endif

  retval = send_establish_intro_cell(circuit);
  if (retval < 0) {
    log_warn(LD_BUG, "XXX");
    circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_INTERNAL);
    return;
  }

  /* We've attempted to use this circuit */
  /* XXX Wtf why */
  pathbias_count_use_attempt(circuit);
}

