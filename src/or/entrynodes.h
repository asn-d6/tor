/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file guardnodes.h
 * \brief Header file for circuitbuild.c.
 **/

#ifndef TOR_ENTRYNODES_H
#define TOR_ENTRYNODES_H

#if 1
/* XXXX NM I would prefer that all of this stuff be private to
 * entrynodes.c. */

/** An entry_guard_t represents our information about a chosen long-term
 * first hop, known as a "helper" node in the literature. We can't just
 * use a node_t, since we want to remember these even when we
 * don't have any directory info. */
typedef struct entry_guard_t {
  char nickname[MAX_NICKNAME_LEN+1];
  char identity[DIGEST_LEN];
  time_t chosen_on_date; /**< Approximately when was this guard added?
                          * "0" if we don't know. */
  char *chosen_by_version; /**< What tor version added this guard? NULL
                            * if we don't know. */
  unsigned int made_contact : 1; /**< 0 if we have never connected to this
                                  * router, 1 if we have. */
  unsigned int can_retry : 1; /**< Should we retry connecting to this entry,
                               * in spite of having it marked as unreachable?*/
  unsigned int path_bias_notice : 1; /**< Did we alert the user about path bias
                                      * for this node already? */
  unsigned int path_bias_disabled : 1; /**< Have we disabled this node because
                                        * of path bias issues? */
  time_t bad_since; /**< 0 if this guard is currently usable, or the time at
                      * which it was observed to become (according to the
                      * directory or the user configuration) unusable. */
  time_t unreachable_since; /**< 0 if we can connect to this guard, or the
                             * time at which we first noticed we couldn't
                             * connect to it. */
  time_t last_attempted; /**< 0 if we can connect to this guard, or the time
                          * at which we last failed to connect to it. */

  unsigned first_hops; /**< Number of first hops this guard has completed */
  unsigned circuit_successes; /**< Number of successfully built circuits using
                               * this guard as first hop. */
} entry_guard_t;

entry_guard_t *entry_guard_get_by_id_digest(const char *digest);
void entry_guards_changed(void);
const smartlist_t *get_entry_guards(void);
int num_live_entry_guards(void);

#endif

void entry_guards_compute_status(const or_options_t *options, time_t now);
int entry_guard_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now);
void entry_nodes_should_be_added(void);
int entry_list_is_constrained(const or_options_t *options);
const node_t *choose_random_entry(cpath_build_state_t *state);
int entry_guards_parse_state(or_state_t *state, int set, char **msg);
void entry_guards_update_state(or_state_t *state);
int getinfo_helper_entry_guards(control_connection_t *conn,
                                const char *question, char **answer,
                                const char **errmsg);

void mark_bridge_list(void);
void sweep_bridge_list(void);

int routerinfo_is_a_configured_bridge(const routerinfo_t *ri);
int node_is_a_configured_bridge(const node_t *node);
void learned_router_identity(const tor_addr_t *addr, uint16_t port,
                             const char *digest);
struct smartlist_t;
void bridge_add_from_config(const tor_addr_t *addr, uint16_t port,
                            const char *digest,
                            const char *transport_name,
                            struct smartlist_t *socks_args);
void retry_bridge_descriptor_fetch_directly(const char *digest);
void fetch_bridge_descriptors(const or_options_t *options, time_t now);
void learned_bridge_descriptor(routerinfo_t *ri, int from_cache);
int any_bridge_descriptors_known(void);
int any_pending_bridge_descriptor_fetches(void);
int entries_known_but_down(const or_options_t *options);
void entries_retry_all(const or_options_t *options);

const smartlist_t *get_socks_args_by_bridge_addrport(const tor_addr_t *addr,
                                                     uint16_t port);

int any_bridges_dont_support_microdescriptors(void);

void entry_guards_free_all(void);

const char *find_transport_name_by_bridge_addrport(const tor_addr_t *addr,
                                                   uint16_t port);
struct transport_t;
int get_transport_by_bridge_addrport(const tor_addr_t *addr, uint16_t port,
                                      const struct transport_t **transport);

int validate_pluggable_transports_config(void);

#endif

