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

void dos_new_client_conn(const tor_addr_t *addr);
void dos_close_client_conn(const tor_addr_t *addr);

void dos_client_stats_free(struct dos_client_stats_t *obj);

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

void dos_cc_init(void);
void dos_cc_free_all(void);

void dos_cc_new_create_cell(channel_t *channel);

#endif /* TOR_DOS_H */

