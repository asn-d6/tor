/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendmid.h
 * \brief Header file for rendmid.c.
 **/

#ifndef TOR_RENDMID_H
#define TOR_RENDMID_H

int rend_mid_establish_intro(or_circuit_t *circ, const uint8_t *request,
                             size_t request_len);
int rend_mid_establish_intro_legacy(or_circuit_t *circ, const uint8_t *request, 
                                    size_t request_len);
int rend_mid_establish_intro_p224(or_circuit_t *circ, const uint8_t *request, 
                                  size_t request_len);
int throw_circuit_error(or_circuit_t *circ, int reason);
int rend_mid_introduce(or_circuit_t *circ, const uint8_t *request,
                       size_t request_len);
int rend_mid_establish_rendezvous(or_circuit_t *circ, const uint8_t *request,
                                  size_t request_len);
int rend_mid_rendezvous(or_circuit_t *circ, const uint8_t *request,
                        size_t request_len);

#endif

