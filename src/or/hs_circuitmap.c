/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 * \brief Functions to manage rendezvous/introduction circuits.
 **/

#define HS_CIRCUITMAP_PRIVATE

#include "or.h"
#include "config.h"
#include "circuitlist.h"
#include "hs_circuitmap.h"

/************************** HS circuitmap code ****************************/

/* This is the hidden service circuitmap. It's a hash table that maps
   introduction and rendezvous tokens to specific circuits such that given a
   token it's easy to find the corresponding circuit. */
static struct hs_circuitmap_ht *the_hs_circuitmap = NULL;
HT_HEAD(hs_circuitmap_ht, or_circuit_t);

/* This is a helper function used by the hash table code (HT_). It returns 1 if
 * two circuits have the same HS token. */
static int
hs_circuits_have_same_token(const or_circuit_t *first_circuit,
                            const or_circuit_t *second_circuit)
{
  hs_token_t *first_token;
  hs_token_t *second_token;

  tor_assert(first_circuit);
  tor_assert(second_circuit);

  first_token = first_circuit->hs_token;
  second_token = second_circuit->hs_token;

  /* Both circs must have a token */
  if (!first_token || !second_token) {
    return 0;
  }

  if (first_token->type != second_token->type)
    return 0;

  if (first_token->token_len != second_token->token_len)
    return 0;

  return tor_memeq(first_token->token,
                   second_token->token,
                   first_token->token_len);
}

/* This is a helper function for the hash table code (HT_). It hashes a circuit
   HS token into an unsigned int for use as a key by the hash table routines. */
static inline unsigned int
hs_circuit_hash_token(const or_circuit_t *circuit)
{
  tor_assert(circuit->hs_token);

  return (unsigned) siphash24g(circuit->hs_token->token,
                               circuit->hs_token->token_len);
}

/* Register the circuitmap hash table */
HT_PROTOTYPE(hs_circuitmap_ht, // The name of the hashtable struct
             or_circuit_t,    // The name of the element struct,
             hs_circuitmap_node,        // The name of HT_ENTRY member
             hs_circuit_hash_token, hs_circuits_have_same_token);

HT_GENERATE2(hs_circuitmap_ht, or_circuit_t, hs_circuitmap_node,
             hs_circuit_hash_token, hs_circuits_have_same_token,
             0.6, tor_reallocarray, tor_free_);


/*************************/

/* Initialize the global HS circuitmap. */
static void
initialize_hs_circuitmap(void)
{
  tor_assert(!the_hs_circuitmap);
  the_hs_circuitmap = tor_malloc_zero(sizeof(struct hs_circuitmap_ht));
  HT_INIT(hs_circuitmap_ht, the_hs_circuitmap);
}

/** Return a new HS token of type <b>type</b> containing <b>token</b>. */
static hs_token_t *
hs_token_new(hs_token_type_t type, size_t token_len,
             const uint8_t *token)
{
  /* XXX memleak */
  hs_token_t *hs_token = tor_malloc_zero(sizeof(hs_token_t));
  hs_token->type = type;
  hs_token->token_len = token_len;
  hs_token->token = tor_memdup(token, token_len);

  return hs_token;
}

/** Free memory allocated by this <b>hs_token</b>. */
static void
hs_token_free(hs_token_t *hs_token)
{
  if (!hs_token) {
    return;
  }

  tor_free(hs_token->token);
  tor_free(hs_token);
}

/** Return the circuit from the circuitmap with token <b>search_token</b>. */
static or_circuit_t *
get_circuit_with_token(hs_token_t *search_token)
{
  /* We use a dummy circuit object for the hash table search routine. */
  or_circuit_t search_circ;
  search_circ.hs_token = search_token;
  return HT_FIND(hs_circuitmap_ht, the_hs_circuitmap, &search_circ);
}

/** Remove this circuit from the HS circuitmap. Specifically, clear its HS
 *  token, and remove it from the hashtable. */
void
hs_circuitmap_remove_circuit(or_circuit_t *circ)
{
  if (!the_hs_circuitmap) {
    return;
  }

  if (!circ || !circ->hs_token) {
    return;
  }

  /* Remove circ from circuitmap */
  or_circuit_t *tmp;
  tmp = HT_REMOVE(hs_circuitmap_ht, the_hs_circuitmap, circ);
  tor_assert(tmp == circ);

  /* Clear token from circ */
  hs_token_free(circ->hs_token);
  circ->hs_token = NULL;
}

/* XXX constify */
/* Steals reference of hs_token */
/* token can be NULL */
/* Helper function that registers <b>circ</b> with <b>token</b> on the HS
   circuitmap. */
static int
hs_circuitmap_register_impl(or_circuit_t *circ,
                            hs_token_t *token)
{
  tor_assert(circ);
  tor_assert(token);

  /* Initialize circuitmap if needed. */
  if (!the_hs_circuitmap) {
    initialize_hs_circuitmap();
  }

  /* If this circuit already has a token, clear it. */
  if (circ->hs_token) {
    hs_circuitmap_remove_circuit(circ);
  }

  /* Check circuitmap to see if we already have a circuit with this token. If
     there is one, clear and kill that circuit. */
  {
    or_circuit_t *found_circ;
    found_circ = get_circuit_with_token(token);
    if (found_circ) {
      hs_circuitmap_remove_circuit(found_circ);
      if (!found_circ->base_.marked_for_close) {
        circuit_mark_for_close(TO_CIRCUIT(found_circ), END_CIRC_REASON_FINISHED);
      }
    }
  }

  /* Register circuit and token to circuitmap. */
  circ->hs_token = token;
  HT_INSERT(hs_circuitmap_ht, the_hs_circuitmap, circ);

  return 0;
}

/** Register <b>circ</b> of <b>type</b> on the HS circuitmap. Use the HS
 *  <b>token</b> as the key to the hash table.  If <b>token</b> is not set,
 *  clear the circuit of any HS tokens. */
static void
hs_circuitmap_register_circuit(or_circuit_t *circ,
                               hs_token_type_t type,
                               size_t token_len,
                               const uint8_t *token)
{
  hs_token_t *hs_token = NULL;

  /* If this function is called with no token, we just want to clear the
     existing token in this circuit. */
  /* XXX Why this functionality? */
  if (!token) {
    hs_circuitmap_remove_circuit(circ);
    return
  }

  /* Create a new token and register it to the circuitmap */
  hs_token = hs_token_new(type, token_len, token);
  tor_assert(hs_token);
  hs_circuitmap_register_impl(circ, hs_token);
}

static or_circuit_t *
hs_circuitmap_get_circuit(hs_token_type_t type,
                          size_t token_len,
                          const uint8_t *token,
                          uint8_t wanted_circ_purpose)
{
  or_circuit_t *found_circ = NULL;

  if (!the_hs_circuitmap) {
    return NULL;
  }

  /* Check the circuitmap if we have a circuit with this token */
  {
    hs_token_t *search_hs_token = hs_token_new(type, token_len, token);
    tor_assert(search_hs_token);
    found_circ = get_circuit_with_token(search_hs_token);
    hs_token_free(search_hs_token);
  }

  if (!found_circ ||
      found_circ->base_.purpose != wanted_circ_purpose ||
      found_circ->base_.marked_for_close) {
    return NULL;
  }

  /* XXX Additional checks are in circuit_get_by_rend_token_and_purpose() */

  return found_circ;
}

/******************************************************************/

/** Return the circuit waiting for intro cells of the given digest.
 * Return NULL if no such circuit is found. */
or_circuit_t *
hs_circuitmap_get_intro_circ_v3(ed25519_public_key_t *auth_key)
{
  tor_assert(auth_key);

  return hs_circuitmap_get_circuit(HS_TOKEN_INTRO_V3,
                                   ED25519_PUBKEY_LEN, auth_key->pubkey,
                                   CIRCUIT_PURPOSE_INTRO_POINT);
}

/** Return the circuit waiting for intro cells of the given digest.
 * Return NULL if no such circuit is found. */
or_circuit_t *
hs_circuitmap_get_intro_circ_v2(const uint8_t *digest)
{
  return hs_circuitmap_get_circuit(HS_TOKEN_INTRO_V2,
                                   REND_TOKEN_LEN, digest,
                                   CIRCUIT_PURPOSE_INTRO_POINT);
}

/** Return the circuit waiting for a rendezvous with the provided cookie.
 * Return NULL if no such circuit is found. */
or_circuit_t *
hs_circuitmap_get_rend_circ(const uint8_t *cookie)
{
  return hs_circuitmap_get_circuit(HS_TOKEN_REND,
                                   REND_TOKEN_LEN, cookie,
                                   CIRCUIT_PURPOSE_REND_POINT_WAITING);
}

/** Set the rendezvous cookie of <b>circ</b> to <b>cookie</b>.  If another
 * circuit previously had that cookie, mark it. */
void
hs_circuitmap_register_rend_circ(or_circuit_t *circ, const uint8_t *cookie)
{
  hs_circuitmap_register_circuit(circ,
                                 HS_TOKEN_REND,
                                 REND_TOKEN_LEN, cookie);
}

/** Set the intro point key digest of <b>circ</b> to <b>cookie</b>.  If another
 * circuit previously had that intro point digest, mark it. */
void
hs_circuitmap_register_intro_circ_v2(or_circuit_t *circ, const uint8_t *digest)
{
  hs_circuitmap_register_circuit(circ,
                                 HS_TOKEN_INTRO_V2,
                                 REND_TOKEN_LEN, digest);
}

/** Set the intro point key digest of <b>circ</b> to <b>cookie</b>.  If another
 * circuit previously had that intro point digest, mark it. */
void
hs_circuitmap_register_intro_circ_v3(or_circuit_t *circ,
                                     const ed25519_public_key_t *auth_key)
{
  hs_circuitmap_register_circuit(circ, HS_TOKEN_INTRO_V3,
                                 ED25519_PUBKEY_LEN,
                                 auth_key->pubkey);
}

void
hs_circuitmap_free_all(void)
{
  ; /* XXX */
}
