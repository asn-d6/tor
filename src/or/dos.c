/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file dos.c
 * \brief Implement Denial of Service mitigation subsystem.
 */

#define DOS_PRIVATE

#include "or.h"
#include "networkstatus.h"

#include "dos.h"

/*
 * Circuit creation denial of service mitigation.
 *
 * Namespace used for this mitigation framework is "dos_cc_" where "cc" is for
 * Circuit Creation.
 */

/* Is the circuit creation DoS mitigation enabled? */
static unsigned int dos_cc_enabled = 0;

/* Consensus parameters. They can be changed when a new consensus arrives.
 * They are initialized with the hardcoded default values. */
static uint32_t dos_cc_min_concurrent_conn;
static uint32_t dos_cc_circuit_time_rate;
static uint32_t dos_cc_circuit_max_count;
static uint32_t dos_cc_defense_type;
static int32_t dos_cc_defense_time_period;

/* Return true iff the circuit creation mitigation is enabled. We look at the
 * consensus for this else a default value is returned. */
static unsigned int
cc_is_enabled(void)
{
  return !!networkstatus_get_param(NULL, "dos_cc_enabled",
                                   DOS_CC_ENABLED_DEFAULT, 0, 1);
}

/* Return the consensus parameter for the minimum concurrent connection at
 * which we'll start counting circuit for the a specific client address. */
static uint32_t
get_ns_param_cc_min_concurrent_connection(void)
{
  return networkstatus_get_param(NULL, "dos_cc_min_concurrent_conn",
                                 DOS_CC_MIN_CONCURRENT_CONN_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the consensus parameter for the time rate that is how many circuits
 * over this time span. */
static uint32_t
get_ns_param_cc_circuit_time_rate(void)
{
  /* This is in seconds. */
  return networkstatus_get_param(NULL, "dos_cc_circuit_time_rate",
                                 DOS_CC_CIRCUIT_TIME_RATE_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the consensus parameter for the maximum circuit count for the
 * circuit time rate. */
static uint32_t
get_ns_param_cc_circuit_max_count(void)
{
  return networkstatus_get_param(NULL, "dos_cc_circuit_max_count",
                                 DOS_CC_CIRCUIT_MAX_COUNT_DEFAULT,
                                 1, INT32_MAX);
}

/* Return the consensus parameter of the circuit creation defense type. */
static uint32_t
get_ns_param_cc_defense_type(void)
{
  /* Time in seconds. */
  return networkstatus_get_param(NULL, "dos_cc_defense_type",
                                 DOS_CC_DEFENSE_TYPE_DEFAULT,
                                 0, 1);
  /* XXX: Use defines for these max and min. */
}

/* Return the consensus parameter of the defense time period which is how much
 * time should we defend against a malicious client address. */
static int32_t
get_ns_param_cc_defense_time_period(void)
{
  /* Time in seconds. */
  return networkstatus_get_param(NULL, "dos_cc_defense_time_period",
                                 DOS_CC_DEFENSE_TIME_PERIOD_DEFAULT,
                                 0, INT32_MAX);
}

/* Set circuit creation parameters located in the consensus or their default
 * if none are present. Called at initialization or when the consensus
 * changes. */
static void
cc_set_parameters_from_ns(void)
{
  /* Get the default consensus param values. */
  dos_cc_min_concurrent_conn = get_ns_param_cc_min_concurrent_connection();
  dos_cc_circuit_time_rate = get_ns_param_cc_circuit_time_rate();
  dos_cc_circuit_max_count = get_ns_param_cc_circuit_max_count();
  dos_cc_defense_time_period = get_ns_param_cc_defense_time_period();
  dos_cc_defense_type = get_ns_param_cc_defense_type();
}

/* Free everything for the circuit creation DoS mitigation subsystem. */
static void
cc_free_all(void)
{
  /* If everything is freed, the circuit creation subsystem is not enabled. */
  dos_cc_enabled = 0;
}

/* Initialize the circuit creation DoS mitigation subsystem. */
static void
cc_init(void)
{
  /* At least get the defaults set up. */
  cc_set_parameters_from_ns();
  dos_cc_enabled = 1;
}

/* Called when the consensus has changed. Do appropriate actions for the
 * circuit creation subsystem. */
static void
cc_consensus_has_changed(void)
{
  /* Looking at the consensus, is the circuit creation subsystem enabled?  If
   * not, we'll clean up. */
  if (!cc_is_enabled()) {
    cc_free_all();
    goto end;
  }

  /* If we were enabled, time to get the parameters again. Else, we just
   * became enabled so we need to initialize. */
  if (dos_cc_enabled) {
    cc_set_parameters_from_ns();
  } else {
    cc_init();
  }

 end:
  return;
}

/* General API */

/* Called when a the consensus has changed. We might have new consensus
 * parameters to look at. */
void
dos_consensus_has_changed(void)
{
  cc_consensus_has_changed();
}

/* Free everything from the Denial of Service subsystem. */
void
dos_free_all(void)
{
  /* Free the circuit creation mitigation subsystem. It is safe to do this
   * even if it wasn't initialized. */
  cc_free_all();
}

/* Initialize the Denial of Service subsystem. */
void
dos_init(void)
{
  if (cc_is_enabled()) {
    cc_init();
  }
}

