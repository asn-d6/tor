/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file dos.h
 * \brief Header file for dos.c
 */

#ifndef TOR_DOS_H
#define TOR_DOS_H

/* General API. */

/* Stub so the pointer is opaque. The geoip subsystem uses this in the per-IP
 * client map. */
struct dos_client_stats_t;

void dos_init(void);
void dos_free_all(void);
void dos_consensus_has_changed(void);
void dos_cleanup(time_t now);
int dos_enabled(void);
void dos_log_heartbeat(void);

void dos_new_client_conn(const tor_addr_t *addr);
void dos_close_client_conn(const tor_addr_t *addr);

void dos_client_stats_free(struct dos_client_stats_t *obj);

int dos_should_refuse_tor2web_client(void);
void dos_note_refuse_tor2web_client(void);

/*
 * Circuit creation DoS mitigation subsystemn interface.
 */

/* dos_cc_enabled, that feature is disabled by default. */
#define DOS_CC_ENABLED_DEFAULT 0
/* dos_cc_defense_type maps to the dos_cc_defense_type_t enum. */
#define DOS_CC_DEFENSE_TYPE_DEFAULT 1
/* dos_cc_min_concurrent_conn */
#define DOS_CC_MIN_CONCURRENT_CONN_DEFAULT 3
/* dos_cc_circuit_time_rate in seconds. */
#define DOS_CC_CIRCUIT_TIME_RATE_DEFAULT 30
/* dos_cc_circuit_max_count is set to 2 circuits a second. */
#define DOS_CC_CIRCUIT_MAX_COUNT_DEFAULT \
  (2 * DOS_CC_CIRCUIT_TIME_RATE_DEFAULT)
/* dos_cc_defense_time_period in seconds. */
#define DOS_CC_DEFENSE_TIME_PERIOD_DEFAULT (60 * 60)

/* Type of defense that we can use for the circuit creation DoS mitigation. */
typedef enum dos_cc_defense_type_t {
  /* No defense used. */
  DOS_CC_DEFENSE_NONE             = 0,
  /* Refuse any cells which means a DESTROY cell will be sent back. */
  DOS_CC_DEFENSE_REFUSE_CELL      = 1,

  /* Maximum value that can be used. Useful for the boundaries of the
   * consensus parameter. */
  DOS_CC_DEFENSE_MAX              = 1,
} dos_cc_defense_type_t;

void dos_cc_init(void);
void dos_cc_free_all(void);

void dos_cc_new_create_cell(channel_t *channel);
dos_cc_defense_type_t dos_cc_assess_circuit(circuit_t *circ);

/*
 * Concurrent connection DoS mitigation interface.
 */

/* dos_conn_enabled which if off by default. */
#define DOS_CONN_ENABLED_DEFAULT 0
/* dos_conn_max_concurrent_count */
#define DOS_CONN_MAX_CONCURRENT_COUNT_DEFAULT 100
/* dos_conn_defense_type_t maps to the dos_conn_defense_type_t enum. */
#define DOS_CONN_DEFENSE_TYPE_DEFAULT 1

/* Type of defense that we can use for the concurrent connection DoS
 * mitigation. */
typedef enum dos_conn_defense_type_t {
  /* No defense used. */
  DOS_CONN_DEFENSE_NONE             = 0,
  /* Close immediately the connection meaning refuse it. */
  DOS_CONN_DEFENSE_CLOSE            = 1,

  /* Maximum value that can be used. Useful for the boundaries of the
   * consensus parameter. */
  DOS_CONN_DEFENSE_MAX              = 1,
} dos_conn_defense_type_t;

dos_conn_defense_type_t dos_conn_permits_address(const tor_addr_t *addr);

#endif /* TOR_DOS_H */

