/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared-random.c
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 **/

#include "shared-random.h"

/* String representation of a protocol phase. */
static const char *phase_str[] = { "commit", "reveal" };

/* String representation of a shared random value status. */
static const char *srv_status_str[] = { "fresh", "non-fresh" };

/* Default filename of the shared random state on disk. */
static const char *default_fname = "sr-state";
/* Constant static seed of the shared random value. */
static const char *srv_seed = "shared-random";
/* Disaster shared random value seed. */
static const char *disaster_seed = "shared-random-disaster";

/* Return a string representation of a srv status. */
static const char *
get_srv_status_str(sr_srv_status_t status)
{
  switch (status) {
  case SR_SRV_STATUS_FRESH:
  case SR_SRV_STATUS_NONFRESH:
    return srv_status_str[status];
  default:
    /* Unknown status shouldn't be possible. */
    tor_assert(0);
  }
}

/* Return a string representation of a protocol phase. */
static const char *
get_phase_str(sr_phase_t phase)
{
  switch (phase) {
  case SR_PHASE_COMMIT:
  case SR_PHASE_REVEAL:
    return phase_str[phase];
  default:
    /* Unknown phase shouldn't be possible. */
    tor_assert(0);
  }
}

/* Return a phase value from a name string. */
static sr_phase_t
get_phase_from_str(const char *name)
{
  int i;
  sr_phase_t phase = -1;

  tor_assert(name);

  for (i = 0; i < ARRAY_LENGTH(phase_str); i++) {
    if (!strcmp(name, phase_str[i])) {
      phase = i;
      break;
    }
  }
  return phase;
}

/* Return a status value from a string. */
static sr_srv_status_t
get_status_from_str(const char *name)
{
  int i;
  sr_srv_status_t status;

  tor_assert(name);

  for (i = 0; i < ARRAY_LENGTH(srv_status_str); i++) {
    if (!strcmp(name, srv_status_str[i])) {
      status = i;
      break;
    }
  }
  return status;
}
