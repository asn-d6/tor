/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file dos.c
 * \brief Implement Denial of Service mitigation subsystem.
 */

#define DOS_PRIVATE

#include "or.h"
#include "config.h"
#include "geoip.h"
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

/* Structure that keeps stats of client connection per-IP. */
typedef struct cc_client_stats_t {
  /* Concurrent connection count from the specific address. 2^32 is most
   * likely way to big for the amount of allowed file descriptors. */
  uint32_t concurrent_count;

  /* Number of allowed circuit rate that is this value is refilled at a rate
   * defined by the consensus plus a bit of random. It is decremented every
   * time a new circuit is seen for this client address and if the count goes
   * to 0, we have a positive detection. */
  uint32_t circuit_bucket;

  /* When was the last time we've refilled the circuit bucket? This is used to
   * know if we need to refill the bucket when a new circuit is seen. */
  time_t last_circ_bucket_refill_ts;
} cc_client_stats_t;

/*
 * General interface of the denial of service mitigation subsystem.
 */

/* This object is a top level object that contains everything related to the
 * per-IP client DoS mitigation. Because it is per-IP, is it used in the geoip
 * clientmap_entry_t object and opaque to that subsystem. */
typedef struct dos_client_stats_t {
  /* Circuit creation statistics. This is set only if the circuit creation
   * subsystem has been enabled (dos_cc_enabled). */
  cc_client_stats_t *cc_stats;
} dos_client_stats_t;

/* Free a circuit creation client connection object. */
static void
cc_client_stats_free(cc_client_stats_t *obj)
{
  if (obj == NULL) {
    return;
  }
  tor_free(obj);
}

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

/* Given the circuit creation client statistics object, refill the cirucit
 * bucket if needed. This also works if the bucket was never filled in the
 * first place. The addr is only used for logging purposes. */
static void
cc_stats_refill_bucket(cc_client_stats_t *stats, const tor_addr_t *addr)
{
  uint32_t new_circuit_bucket_count;
  double circuit_rate = 0.0, num_token;
  time_t now, elapsed_time_last_refill;

  tor_assert(stats);
  tor_assert(addr);

  now = approx_time();

  /* We've never filled the bucket so fill it with the expected number and we
   * are done. */
  if (stats->last_circ_bucket_refill_ts == 0) {
    num_token = dos_cc_circuit_max_count;
    goto end;
  }

  /* At this point, we know we need to add token to the bucket. We'll first
   * compute the circuit rate that is how many circuit are we allowed to do
   * per second. For this, we take the maximum count and time rate from the
   * consensus. */
  circuit_rate = (double) dos_cc_circuit_max_count /
                 (double) dos_cc_circuit_time_rate;
  /* Safety checks here. 2^16 circuits per second is insanely high so cap it
   * just to be safe. Because the above is controlled by the consensus, this
   * should really never happens. */
  if (BUG(circuit_rate >= UINT16_MAX)) {
    circuit_rate = UINT16_MAX;
  }

  /* How many seconds have elapsed between now and the last refill? */
  elapsed_time_last_refill = now - stats->last_circ_bucket_refill_ts;

  /* We cap this to the circuit time rate else an attacker could connect once,
   * wait 2 days for which the circuit bucket will fill up continously and
   * then start a circuit creaton DoS. */
  if (elapsed_time_last_refill > dos_cc_circuit_time_rate) {
    elapsed_time_last_refill = dos_cc_circuit_time_rate;
  }

  /* Compute how many circuits we are allowed in that time frame which we'll
   * add to the bucket. We want it to be rounded down to an integer. For
   * example, if we have 0.8 circuits allowed, it is clamped down to 0. */
  num_token = elapsed_time_last_refill * circuit_rate;

 end:
  /* We cap the bucket to the maxium circuit count else this could grow to
   * infinity over time. We want the new tokens clamped down to uint32_t so we
   * get an integer value. */
  new_circuit_bucket_count = MIN(stats->circuit_bucket + (uint32_t) num_token,
                                 dos_cc_circuit_max_count);
  log_debug(LD_DOS, "DoS address %s has its circuit bucket value: %" PRIu32
                    ". Filling it to %" PRIu32 ". Circuit rate is %.2f",
            fmt_addr(addr), stats->circuit_bucket, new_circuit_bucket_count,
            circuit_rate);

  stats->circuit_bucket = new_circuit_bucket_count;
  stats->last_circ_bucket_refill_ts = now;
  return;
}

/* Called when a new client connection has been established. Allocate the
 * circuit creation statistics object if needed in the stats object. The
 * address addr is for logging purposes only. */
static void
cc_new_client_conn(const tor_addr_t *addr, dos_client_stats_t *stats)
{
  tor_assert(addr);
  tor_assert(stats);

  if (stats->cc_stats == NULL) {
    stats->cc_stats = tor_malloc_zero(sizeof(cc_client_stats_t));
    /* Fill up the bucket to the expected values since this is a brand new
     * connection. */
    cc_stats_refill_bucket(stats->cc_stats, addr);
  }
  stats->cc_stats->concurrent_count++;

  log_debug(LD_DOS, "Client address %s has now %u concurrent connections.",
            fmt_addr(addr), stats->cc_stats->concurrent_count);
}

/* Called when a new client connection has been established. Allocate the
 * circuit creation statistics object if needed in the stats object. The
 * address addr is for logging purposes only. */
static void
cc_close_client_conn(const tor_addr_t *addr, dos_client_stats_t *stats)
{
  tor_assert(addr);
  tor_assert(stats);

  /* Nothing to do here. */
  if (stats->cc_stats == NULL) {
    goto end;
  }

  /* Because the new client connection is noted when the channel becomes open,
   * this means we can end up here if the connection was closed before it was
   * ever opened leading to having this down to 0. Just ignore. */
  if (stats->cc_stats->concurrent_count == 0) {
    goto end;
  }

  stats->cc_stats->concurrent_count--;
  log_debug(LD_DOS, "Client address %s has lost a connection. Concurrent "
                    "connections are now at %u",
            fmt_addr(addr), stats->cc_stats->concurrent_count);

 end:
  return;
}

/* General private API */

/* Return true iff we have at least one DoS detection enabled. This is used to
 * decide if we need to allocate any kind of high level DoS object. */
static inline int
dos_is_enabled(void)
{
  return !!dos_cc_enabled;
}

/* General API */

/* Called when a new client connection has been established on the given
 * address. */
void
dos_new_client_conn(const tor_addr_t *addr)
{
  clientmap_entry_t *entry;

  tor_assert(addr);

  /* Past that point, we know we have at least one DoS detection subsystem
   * enabled so we'll start allocating stuff. */
  if (!dos_is_enabled()) {
    goto end;
  }

  /* We are only interested in client connection from the geoip cache. */
  entry = geoip_lookup_client(addr, NULL, GEOIP_CLIENT_CONNECT);
  if (BUG(entry == NULL)) {
    /* Should never happen because we note down the address in the geoip
     * cache before this is called. */
    goto end;
  }

  /* It might be the first time we see this address so allocate a DoS client
   * address statistics object. */
  if (entry->dos_stats == NULL) {
    entry->dos_stats = tor_malloc_zero(sizeof(dos_client_stats_t));
  }

  /* If we have the circuit creation detection enabled, notify it. */
  if (dos_cc_enabled) {
    cc_new_client_conn(addr, entry->dos_stats);
  }

 end:
  return;
}

/* Called when a client connection for the given IP address has been closed. */
void
dos_close_client_conn(const tor_addr_t *addr)
{
  clientmap_entry_t *entry;

  tor_assert(addr);

  /* Past that point, we know we have at least one DoS detection subsystem so
   * we should lookup anything related to this address. */
  if (!dos_is_enabled()) {
    goto end;
  }

  /* We are only interested in client connection from the geoip cache. */
  entry = geoip_lookup_client(addr, NULL, GEOIP_CLIENT_CONNECT);
  if (entry == NULL) {
    /* This can happen because we can close a connection before the channel
     * got to be noted down in the geoip cache. */
    goto end;
  }

  /* This could happen if we free a connection object before the channel was
   * ever opened. */
  if (entry->dos_stats == NULL) {
    goto end;
  }

  /* If we have the circuit creation detection enabled, notify it. */
  if (dos_cc_enabled) {
    cc_close_client_conn(addr, entry->dos_stats);
  }

 end:
  return;
}

/* Free the given dos_client_stats_t object. */
void
dos_client_stats_free(dos_client_stats_t *obj)
{
  if (obj == NULL) {
    return;
  }
  cc_client_stats_free(obj->cc_stats);
  tor_free(obj);
}

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

