/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.h
 * \brief Header file for hs_circuitmap.c.
 **/

#ifndef TOR_HS_CIRCUITMAP_H
#define TOR_HS_CIRCUITMAP_H

or_circuit_t *hs_circuitmap_get_rend_circ(const uint8_t *cookie);
or_circuit_t *hs_circuitmap_get_intro_circ_v3(ed25519_public_key_t *auth_key);
or_circuit_t *hs_circuitmap_get_intro_circ_v2(const uint8_t *digest);

void hs_circuitmap_register_rend_circ(or_circuit_t *circ, const uint8_t *cookie);
void hs_circuitmap_register_intro_circ_v2(or_circuit_t *circ, const uint8_t *digest);
void hs_circuitmap_register_intro_circ_v3(or_circuit_t *circ,
                                        const ed25519_public_key_t *auth_key);

void hs_circuitmap_remove_circuit(or_circuit_t *circ);

#endif
