/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.h
 * \brief Header file for hs_circuit.c.
 **/


/* DOCDOCDOC */
typedef enum {
  HS_TOKEN_INTRO,
  HS_TOKEN_REND
} hs_token_type_t;

/** Represents a token used in the HS protocol. Each such token maps to a
 *  specific introduction or rendezvous circuit. */
typedef struct hs_token_t {
  HT_ENTRY(hs_token_t) node;

  /* The HS protocol version that uses this token.
   *
   * The version value is 2 for the old HS version, and 3 for next generation
   * hidden services.
   *
   * The size of the hs_token depends on the HS protocol version and the type
   * of token:
   *  Old HS protocol uses 128bit tokens for introduction and rendezvous.
   *  New HS protocol uses 128bit tokens for rendezvous, and 256bit tokens for
   *  introductions. */
  int version;

  /* Type of token. Can be a rendezvous or introduction token. */
  hs_token_type_t type;

  /* The size of the token */
  size_t token_len;

  /* The token itself. Memory allocated at runtime depending on the HS version. */
  uint8_t *hs_token;
} hs_token_t;
