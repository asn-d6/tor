/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_intropoint.h
 * \brief Header file for hs_intropoint.c.
 **/

#ifndef TOR_HSINTRO_H
#define TOR_HSINTRO_H

int hs_received_establish_intro(or_circuit_t *circ, const uint8_t *request,
                             size_t request_len);


#ifdef HS_INTROPOINT_PRIVATE

STATIC int
verify_establish_intro_cell(hs_establish_intro_cell_t *out,
                            const char *circuit_key_material,
                            size_t circuit_key_material_len);

#endif

#endif
