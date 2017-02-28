#ifndef TOR_HS_NTOR_H
#define TOR_HS_NTOR_H

#include "or.h"

/* Key material needed to encode/decode INTRODUCE1 cells */
typedef struct {
  /* Key used for encryption of encrypted INTRODUCE1 blob */
  uint8_t enc_key[CIPHER256_KEY_LEN];
  /* MAC key used to protect encrypted INTRODUCE1 blob */
  uint8_t mac_key[DIGEST256_LEN];
} intro1_key_material_t;

/* Key material needed to encode/decode RENDEZVOUS1 cells */
typedef struct {
  /* This is the MAC of the HANDSHAKE_INFO field */
  uint8_t rend_cell_auth_mac[DIGEST256_LEN];
  /* This is the key seed used to derive further rendezvous crypto keys as
   * detailed in section 4.2.1 of rend-spec-ng.txt. */
  uint8_t ntor_key_seed[DIGEST256_LEN];
} rend1_key_material_t;

int
hs_ntor_client_get_introduce1_keys(
                      const ed25519_public_key_t *intro_auth_pubkey,
                      const curve25519_public_key_t *intro_enc_pubkey,
                      const curve25519_keypair_t *client_ephemeral_enc_keypair,
                      const uint8_t *subcredential,
                      intro1_key_material_t *intro1_key_material_out);

int hs_ntor_client_get_rendezvous1_keys(
                  const ed25519_public_key_t *intro_auth_pubkey,
                  const curve25519_keypair_t *client_ephemeral_enc_keypair,
                  const curve25519_public_key_t *intro_enc_pubkey,
                  const curve25519_public_key_t *service_ephemeral_rend_pubkey,
                  rend1_key_material_t *rend1_key_material_out);

int hs_ntor_service_get_introduce1_keys(
                  const ed25519_public_key_t *intro_auth_pubkey,
                  const curve25519_keypair_t *intro_enc_keypair,
                  const curve25519_public_key_t *client_ephemeral_enc_pubkey,
                  const uint8_t *subcredential,
                  intro1_key_material_t *intro1_key_material_out);

int hs_ntor_service_get_rendezvous1_keys(
                  const ed25519_public_key_t *intro_auth_pubkey,
                  const curve25519_keypair_t *intro_enc_keypair,
                  const curve25519_keypair_t *service_ephemeral_rend_keypair,
                  const curve25519_public_key_t *client_ephemeral_enc_pubkey,
                  rend1_key_material_t *rend1_key_material_out);

#endif

