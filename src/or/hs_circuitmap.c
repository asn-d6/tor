/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 * \brief Functions to manage rendezvous/introduction circuits
 **/

#define HS_CIRCUIT_PRIVATE

#include "or.h"
#include "hs_circuit.h"

typedef struct hs_circuitmap_t {
  /* Hash table to map from HS token to HS circuit */
  HT_HEAD(hs_circuitmap_ht, hs_token_t) hs_circuitmap;
}

int
initialize_hs_circuitmap(void)
{
  ;
}

int
assign_hs_token_to_circuit(uint8_t *token,
                           size_t token_len,
                           hs_token_type_t type,
                           or_circuit_t *circ)
{
  ;
}
