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
#include "hs/cell_establish_intro.h"
#include "hs/cell_common.h"

#define AUTH_KEY_ED25519 2
#define ESTABLISH_INTRO_SIG_PREFIX "Tor establish-intro cell v1"

/* TODO Remove this when these funcs get used. For now they are only used in
   unittests. */
#ifdef TOR_UNIT_TESTS

/** Given an ESTABLISH_INTRO <b>cell</b>, encode it and place its payload in
 *  <b>buf_out</b> which has size <b>buf_out_len</b>. If <b>buf_out</b> is too
 *  small, return -1. Otherwise, return 0 if everything went well. */
STATIC int
get_establish_intro_payload(uint8_t *buf_out, size_t buf_out_len,
                            const hs_cell_establish_intro_t *cell)
{
  if (buf_out_len < RELAY_PAYLOAD_SIZE) {
    return -1;
  }

  ssize_t bytes_used = hs_cell_establish_intro_encode(buf_out, buf_out_len,
                                                      cell);
  if (bytes_used < 0) { /* XXX hiding -2 retval */
    return -1;
  }

  return 0;
}

static void
set_cell_extensions(hs_cell_establish_intro_t *cell)
{
  cell_extension_t *cell_extensions = cell_extension_new();

  hs_cell_establish_intro_set_extensions(cell, cell_extensions);
}

/** Given the circuit handshake info in <b>circuit_key_material</b>, create and
 *  return an ESTABLISH_INTRO cell. Return NULL if something went wrong.  The
 *  returned cell is allocated on the heap and it's the responsibility of the
 *  caller to free it. */
STATIC hs_cell_establish_intro_t *
generate_establish_intro_cell(const char *circuit_key_material,
                              size_t circuit_key_material_len)
{
  hs_cell_establish_intro_t *cell = NULL;

  log_warn(LD_GENERAL,
           "Generating ESTABLISH_INTRO cell (key_material_len: %u)",
           (unsigned) circuit_key_material_len);

  /* Generate short-term keypair for use in ESTABLISH_INTRO */
  ed25519_keypair_t key_struct;
  if(ed25519_keypair_generate(&key_struct, 0) < 0) {
    goto err;
  }

  cell = hs_cell_establish_intro_new();

  /* Set AUTH_KEY_TYPE: 2 means ed25519 */
  hs_cell_establish_intro_set_auth_key_type(cell, AUTH_KEY_ED25519);

  /* Set AUTH_KEY_LEN field */
  /* Must also set byte-length of AUTH_KEY to match */
  int auth_key_len = ED25519_PUBKEY_LEN;
  hs_cell_establish_intro_set_auth_key_len(cell, auth_key_len);
  hs_cell_establish_intro_setlen_auth_key(cell, auth_key_len);

  /* Set AUTH_KEY field */
  uint8_t *auth_key_ptr = hs_cell_establish_intro_getarray_auth_key(cell);
  memcpy(auth_key_ptr, key_struct.pubkey.pubkey, auth_key_len);

  /* No cell extensions needed */
  set_cell_extensions(cell);

  /* Set signature size.
     We need to do this up here, because _encode() needs it and we need to call
     _encode() to calculate the MAC and signature.
  */
  int sig_len = ED25519_SIG_LEN;
  hs_cell_establish_intro_set_sig_len(cell, sig_len);
  hs_cell_establish_intro_setlen_sig(cell, sig_len);

  /* Calculate the cell MAC (aka HANDSHAKE_AUTH). */
  {
    /* To calculate HANDSHAKE_AUTH, we dump the cell in bytes, and then derive
       the MAC from it. */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ssize_t encoded_len;
    char mac[TRUNNEL_SHA3_256_LEN];

    encoded_len = hs_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell.");
      goto err;
    }

    /* sanity check */
    tor_assert(encoded_len > ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN);

    /* Calculate MAC of all fields before HANDSHAKE_AUTH */
    if (crypto_hmac_sha3_256(mac,
                         circuit_key_material, circuit_key_material_len,
                         (const char*)cell_bytes_tmp,
                         encoded_len - (ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN)) < 0) {
      log_warn(LD_BUG, "Unable to generate MAC for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* Write the MAC to the cell */
    uint8_t *handshake_ptr =
      hs_cell_establish_intro_getarray_handshake_mac(cell);
    memcpy(handshake_ptr, mac, sizeof(mac));
  }

  /* Calculate the cell signature */
  {
    /* To calculate the sig we follow the same procedure as above. We first
       dump the cell up to the sig, and then calculate the sig */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ssize_t encoded_len;
    ed25519_signature_t sig;

    encoded_len = hs_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell (2).");
      goto err;
    }

    tor_assert(encoded_len > ED25519_SIG_LEN);

    if (ed25519_sign_prefixed(&sig,
                              (uint8_t*) cell_bytes_tmp,
                              encoded_len - ED25519_SIG_LEN,
                              ESTABLISH_INTRO_SIG_PREFIX,
                              &key_struct)) {
      log_warn(LD_BUG, "Unable to generate signature for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* And write the signature to the cell */
    uint8_t *sig_ptr = hs_cell_establish_intro_getarray_sig(cell);
    memcpy(sig_ptr, sig.sig, sig_len);
  }

  /* We are done! Return the cell! */
  return cell;

 err:
  tor_free(cell);
  return NULL;
}

#endif
