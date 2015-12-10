/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto.h
 *
 * \brief Headers for crypto_rng.c
 **/

#ifndef TOR_CRYPTO_RNG_H
#define TOR_CRYPTO_RNG_H

#include <stdio.h>
#include "torint.h"
#include "compat.h"
#include "crypto_rng.h"

MOCK_DECL(void,crypto_rand,(char *to, size_t n));
void crypto_rand_unmocked(char *to, size_t n);
void crypto_init_shake_prng(void);
void crypto_shake_prng_postfork(void);
void crypto_shake_prng_check_reseed(int force);
void crypto_teardown_shake_prng(void);

#endif

