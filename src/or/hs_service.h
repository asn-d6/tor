/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.h
 * \brief Header file for hs_service.c.
 **/

#ifndef TOR_HSSERVICE_H
#define TOR_HSSERVICE_H

#include "or.h"
#include "hs_establish_intro.h"

void hs_service_intro_has_opened(origin_circuit_t *circuit);

#ifdef HS_SERVICE_PRIVATE

STATIC hs_establish_intro_cell_t *
generate_establish_intro_cell(const char *circuit_key_material,
                              size_t circuit_key_material_len);

#endif

#endif

