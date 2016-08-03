/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service functionality
 **/

#define HS_SERVICE_PRIVATE

#include "or.h"
#include "relay.h"
#include "rendservice.h"
#include "circuitlist.h"
#include "circpathbias.h"

#include "hs_service.h"
#include "hs_establish_intro.h"

#define AUTH_KEY_ED25519 2

/** Given an ESTABLISH_INTRO <b>cell</b>, encode it and place its payload in
 *  <b>buf_out</b> which has size <b>buf_out_len</b>. If <b>buf_out</b> is too
 *  small, return -1. Otherwise, return 0 if everything went well. */
STATIC int
get_establish_intro_payload(uint8_t *buf_out, size_t buf_out_len,
                            const hs_establish_intro_cell_t *cell)
{
  if (buf_out_len < RELAY_PAYLOAD_SIZE) {
    return -1;
  }

  ssize_t bytes_used = hs_establish_intro_cell_encode(buf_out, buf_out_len,
                                                      cell);
  if (bytes_used < 0) { /* XXX hiding -2 retval */
    return -1;
  }

  return 0;
}

/** Given the circuit handshake info in <b>circuit_key_material</b>, create and
 *  return an ESTABLISH_INTRO cell. Return NULL if something went wrong.  The
 *  returned cell is allocated on the heap and it's the responsibility of the
 *  caller to free it. */
STATIC hs_establish_intro_cell_t *
generate_establish_intro_cell(const char *circuit_key_material,
                              size_t circuit_key_material_len)
{
  hs_establish_intro_cell_t *cell = NULL;

  log_warn(LD_GENERAL,
           "Generating ESTABLISH_INTRO cell (key_material_len: %u)",
           (unsigned) circuit_key_material_len);

  /* Generate short-term keypair for use in ESTABLISH_INTRO */
  ed25519_keypair_t key_struct;
  if(ed25519_keypair_generate(&key_struct, 0) < 0) {
    goto err;
  }

  cell = hs_establish_intro_cell_new();

  /* Set AUTH_KEY_TYPE: 2 means ed25519 */
  hs_establish_intro_cell_set_auth_key_type(cell, AUTH_KEY_ED25519);

  /* Set AUTH_KEY_LEN field */
  /* Must also set byte-length of AUTH_KEY to match */
  int auth_key_len = ED25519_PUBKEY_LEN;
  hs_establish_intro_cell_set_auth_key_len(cell, auth_key_len);
  hs_establish_intro_cell_setlen_auth_key(cell, auth_key_len);

  /* Set AUTH_KEY field */
  uint8_t *auth_key_ptr = hs_establish_intro_cell_getarray_auth_key(cell);
  memcpy(auth_key_ptr, key_struct.pubkey.pubkey, auth_key_len);

  /* No cell extensions needed */
  hs_establish_intro_cell_setlen_extensions(cell, 0);
  hs_establish_intro_cell_set_n_extensions(cell, 0);

  /* Set signature size.
     We need to do this up here, because _encode() needs it and we need to call
     _encode() to calculate the MAC and signature.
  */
  int sig_len = ED25519_SIG_LEN;
  hs_establish_intro_cell_set_siglen(cell, sig_len);
  hs_establish_intro_cell_setlen_sig(cell, sig_len);

  /* Calculate the cell MAC (aka HANDSHAKE_AUTH). */
  {
    /* To calculate HANDSHAKE_AUTH, we dump the cell in bytes, and then derive
       the MAC from it. */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ssize_t encoded_len;
    char mac[SHA3_256_MAC_LEN];

    encoded_len = hs_establish_intro_cell_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell.");
      goto err;
    }

    /* sanity check */
    tor_assert(encoded_len > ED25519_SIG_LEN + 2 + SHA3_256_MAC_LEN);

    /* Calculate MAC of all fields before HANDSHAKE_AUTH */
    if (crypto_hmac_sha3_256(mac,
                         circuit_key_material, circuit_key_material_len,
                         (const char*)cell_bytes_tmp,
                         encoded_len - (ED25519_SIG_LEN + 2 + SHA3_256_MAC_LEN)) < 0) {
      log_warn(LD_BUG, "Unable to generate MAC for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* Write the MAC to the cell */
    uint8_t *handshake_ptr =
      hs_establish_intro_cell_getarray_handshake_sha3_256(cell);
    memcpy(handshake_ptr, mac, sizeof(mac));
  }

  /* Calculate the cell signature */
  {
    /* To calculate the sig we follow the same procedure as above. We first
       dump the cell up to the sig, and then calculate the sig */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ssize_t encoded_len;
    ed25519_signature_t sig;

    encoded_len = hs_establish_intro_cell_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell (2).");
      goto err;
    }

    /* XXX These contents are prefixed with the string "Tor establish-intro cell v1". */
    if (ed25519_sign(&sig,
                     (uint8_t*) cell_bytes_tmp, encoded_len - ED25519_SIG_LEN,
                     &key_struct)) {
      log_warn(LD_BUG, "Unable to generate signature for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* And write the signature to the cell */
    uint8_t *sig_ptr = hs_establish_intro_cell_getarray_sig(cell);
    memcpy(sig_ptr, sig.sig, sig_len);
  }

  /* We are done! Return the cell! */
  return cell;

 err:
  tor_free(cell);
  return NULL;
}

/** Send an ESTABLISH_INTRO cell in <b>circuit</b>. */
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

  /* Free the cell object */
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
hs_service_intro_circ_has_opened(origin_circuit_t *circuit)
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

