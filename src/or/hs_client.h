/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_client.h
 * \brief Header file containing client data for the HS subsytem.
 **/

#ifndef TOR_HS_CLIENT_H
#define TOR_HS_CLIENT_H

void hs_client_note_connection_attempt_succeeded(
                                       const edge_connection_t *conn);

typedef struct hs_descriptor_t hs_descriptor_t;
int hs_any_intro_points_usable(const hs_descriptor_t *desc);
int
hs_client_refetch_v3_renddesc(const ed25519_public_key_t *onion_identity_pk);

#endif /* TOR_HS_CLIENT_H */

