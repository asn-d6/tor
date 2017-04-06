/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 **/

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "policies.h"
#include "relay.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"

#include "hs_cell.h"
#include "hs_circuit.h"
#include "hs_ntor.h"
#include "hs_service.h"

/* Trunnel. */
#include "ed25519_cert.h"
#include "hs/cell_common.h"
#include "hs/cell_establish_intro.h"

/* Return the number of opened introduction circuit for the given circuit that
 * is matching its identity key. */
static unsigned int
count_opened_intro_point_circuits(const hs_service_t *service)
{
  unsigned int count = 0;
  origin_circuit_t *ocirc = NULL;

  tor_assert(service);

  while ((ocirc = circuit_get_next_service_intro_circ(ocirc))) {
    /* We only want to count those with a circuit identifier so only v3+
     * ignoring v2 circuits. */
    if (ocirc->hs_ident &&
        ed25519_pubkey_eq(&service->keys.identity_pk,
                          &ocirc->hs_ident->identity_pk)) {
      count++;
    }
  }
  return count;
}

/* From a given service, rendezvous cookie and handshake infor, create a
 * rendezvous point circuit identifier. This can't fail. */
static hs_circ_identifier_t *
create_rp_circuit_identifier(const hs_service_t *service,
                             const uint8_t *rendezvous_cookie,
                             const curve25519_public_key_t *server_pk,
                             const hs_ntor_rend_cell_keys_t *keys)
{
  hs_circ_identifier_t *ident;
  uint8_t handshake_info[CURVE25519_PUBKEY_LEN + DIGEST256_LEN];

  tor_assert(service);
  tor_assert(rendezvous_cookie);
  tor_assert(server_pk);
  tor_assert(keys);

  ident = tor_malloc_zero(sizeof(*ident));
  ed25519_pubkey_copy(&ident->identity_pk, &service->keys.identity_pk);
  /* Copy the RENDEZVOUS_COOKIE which is the unique identifier. */
  memcpy(ident->rendezvous_cookie, rendezvous_cookie,
         sizeof(ident->rendezvous_cookie));
  /* Build the HANDSHAKE_INFO which looks like this:
   *    SERVER_PK        [32 bytes]
   *    AUTH_INPUT_MAC   [32 bytes]
   */
  memcpy(handshake_info, server_pk->public_key, CURVE25519_PUBKEY_LEN);
  memcpy(handshake_info + CURVE25519_PUBKEY_LEN, keys->rend_cell_auth_mac,
         DIGEST256_LEN);
  tor_assert(sizeof(ident->rendezvous_handshake_info) ==
             sizeof(handshake_info));
  memcpy(ident->rendezvous_handshake_info, handshake_info,
         sizeof(ident->rendezvous_handshake_info));
  /* Finally copy the NTOR_KEY_SEED for e2e encryption on the circuit. */
  tor_assert(sizeof(ident->rendezvous_ntor_key_seed) ==
             sizeof(keys->ntor_key_seed));
  memcpy(ident->rendezvous_ntor_key_seed, keys->ntor_key_seed,
         sizeof(ident->rendezvous_ntor_key_seed));
  return ident;
}

/* From a given service and service intro point, create an introduction point
 * circuit identifier. This can't fail. */
static hs_circ_identifier_t *
create_intro_circuit_identifier(const hs_service_t *service,
                                const hs_service_intro_point_t *ip)
{
  hs_circ_identifier_t *ident;

  tor_assert(service);
  tor_assert(ip);

  ident = tor_malloc_zero(sizeof(*ident));
  ed25519_pubkey_copy(&ident->identity_pk, &service->keys.identity_pk);
  if (ip->base.is_only_legacy) {
    ident->auth_key_type = HS_AUTH_KEY_TYPE_LEGACY;
    ident->intro_key.legacy = crypto_pk_copy_full(ip->legacy_key);
  } else {
    ident->auth_key_type = HS_AUTH_KEY_TYPE_ED25519;
    ed25519_pubkey_copy(&ident->intro_key.ed25519_pk,
                        &ip->auth_key_kp.pubkey);
  }

  return ident;
}

/* For a given introduction point and an introduction circuit, send the
 * ESTABLISH_INTRO cell. The service object is used for logging. This can fail
 * and if so, the circuit is closed and the intro point object is flagged
 * that the circuit is not established anymore which is important for the
 * retry mechanism. */
static void
send_establish_intro(const hs_service_t *service,
                     hs_service_intro_point_t *ip, origin_circuit_t *circ)
{
  ssize_t cell_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE];

  tor_assert(service);
  tor_assert(ip);
  tor_assert(circ);

  /* Encode establish intro cell. */
  cell_len = hs_cell_build_establish_intro(circ->cpath->prev->rend_circ_nonce,
                                           ip, payload);
  if (cell_len < 0) {
    log_warn(LD_REND, "Unable to encode ESTABLISH_INTRO cell for service %s "
                      "on circuit %u. Closing circuit.",
             safe_str_client(service->onion_address),
             TO_CIRCUIT(circ)->n_circ_id);
    goto err;
  }

  /* Send the cell on the circuit. */
  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_ESTABLISH_INTRO,
                                   (char *) payload, cell_len,
                                   circ->cpath->prev) < 0) {
    log_info(LD_REND, "Unable to send ESTABLISH_INTRO cell for service %s "
                      "on circuit %u.",
             safe_str_client(service->onion_address),
             TO_CIRCUIT(circ)->n_circ_id);
    /* On error, the circuit has been closed. */
    goto done;
  }

  /* Record the attempt to use this circuit. */
  pathbias_count_use_attempt(circ);
  goto done;

 err:
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
 done:
  memwipe(payload, 0, sizeof(payload));
}

/* From a list of link specifier, an onion key and if we are requesting a
 * direct connection (ex: single onion service), return a newly allocated
 * extend_info_t object. This function checks the firewall policies and if we
 * are allowed to extend to the chosen address.
 *
 *  if either IPv4 or legacy ID is missing, error.
 *  if not direct_conn, IPv4 is prefered.
 *  if direct_conn, IPv6 is prefered if we have one available.
 *  if firewall does not allow the chosen address, error.
 *
 * Return NULL if we can fulfill the conditions. */
static extend_info_t *
get_rp_extend_info(const smartlist_t *link_specifiers,
                   const curve25519_public_key_t *onion_key, int direct_conn)
{
  int have_v4 = 0, have_v6 = 0, have_legacy_id = 0, have_ed25519_id = 0;
  char legacy_id[DIGEST_LEN] = {0};
  uint16_t port_v4 = 0, port_v6 = 0, port = 0;
  tor_addr_t addr_v4, addr_v6, *addr = NULL;
  ed25519_public_key_t ed25519_pk = {0};
  extend_info_t *info = NULL;

  tor_assert(link_specifiers);
  tor_assert(onion_key);

  SMARTLIST_FOREACH_BEGIN(link_specifiers, const link_specifier_t *, ls) {
    switch (link_specifier_get_ls_type(ls)) {
    case LS_IPV4:
      /* Skip if we already seen a v4. */
      if (have_v4) continue;
      tor_addr_from_ipv4h(&addr_v4,
                          link_specifier_get_un_ipv4_addr(ls));
      port_v4 = link_specifier_get_un_ipv4_port(ls);
      have_v4 = 1;
      break;
    case LS_IPV6:
      /* Skip if we already seen a v6. */
      if (have_v6) continue;
      tor_addr_from_ipv6_bytes(&addr_v6,
          (const char *) link_specifier_getconstarray_un_ipv6_addr(ls));
      port_v6 = link_specifier_get_un_ipv6_port(ls);
      have_v6 = 1;
      break;
    case LS_LEGACY_ID:
      /* Make sure we do have enough bytes for the legacy ID. */
      if (link_specifier_getlen_un_legacy_id(ls) < sizeof(legacy_id)) {
        break;
      }
      memcpy(legacy_id, link_specifier_getconstarray_un_legacy_id(ls),
             sizeof(legacy_id));
      have_legacy_id = 1;
      break;
    case LS_ED25519_ID:
      memcpy(ed25519_pk.pubkey,
             link_specifier_getconstarray_un_ed25519_id(ls),
             ED25519_PUBKEY_LEN);
      have_ed25519_id = 1;
      break;
    default:
      /* Ignore unknown. */
      break;
    }
  } SMARTLIST_FOREACH_END(ls);

  /* IPv4, legacy ID and ed25519 are mandatory. */
  if (!have_v4 || !have_legacy_id || !have_ed25519_id) {
    goto done;
  }
  /* By default, we pick IPv4 but this might change to v6 if certain
   * conditions are met. */
  addr = &addr_v4; port = port_v4;

  /* If we are NOT in a direct connection, we'll use our Guard and a 3-hop
   * circuit so we can't extend in IPv6. And at this point, we do have an IPv4
   * address available so go to validation. */
  if (!direct_conn) {
    goto validate;
  }

  /* From this point on, we have a request for a direct connection to the
   * rendezvous point so make sure we can actually connect through our
   * firewall. We'll prefer IPv6. */

  /* IPv6 test. */
  if (have_v6 &&
      fascist_firewall_allows_address_addr(&addr_v6, port_v6,
                                           FIREWALL_OR_CONNECTION, 1, 1)) {
    /* Direct connection and we can reach it in IPv6 so go for it. */
    addr = &addr_v6; port = port_v6;
    goto validate;
  }
  /* IPv4 test and we are sure we have a v4 because of the check above. */
  if (fascist_firewall_allows_address_addr(&addr_v4, port_v4,
                                           FIREWALL_OR_CONNECTION, 0, 0)) {
    /* Direct connection and we can reach it in IPv4 so go for it. */
    addr = &addr_v4; port = port_v4;
    goto validate;
  }

 validate:
  /* We'll validate now that the address we've picked isn't a private one. If
   * it is, are we allowing to extend to private address? */
  if (!extend_info_addr_is_allowed(addr)) {
    log_warn(LD_REND, "Rendezvous point address is private and it is not "
                      "allowed to extend to it: %s:%u",
             fmt_addr(&addr_v4), port_v4);
    goto done;
  }

  /* We do have everything for which we think we can connect successfully. */
  info = extend_info_new(NULL, legacy_id, &ed25519_pk, NULL, onion_key,
                         addr, port);
 done:
  return info;
}

/* For a given service, the ntor onion key and a rendezvous cookie, launch a
 * circuit to the rendezvous point specified by the link specifiers. On
 * success, a circuit identifier is attached to the circuit with the needed
 * data. This function will try to open a circuit for a maximum value of
 * MAX_REND_FAILURES then it will give up. */
static void
launch_rendezvous_point_circuit(const hs_service_t *service,
                                const hs_service_intro_point_t *ip,
                                const curve25519_public_key_t *onion_key,
                                const uint8_t *rendezvous_cookie,
                                const curve25519_public_key_t *client_pk)
{
  int circ_needs_uptime;
  extend_info_t *info = NULL;
  origin_circuit_t *circ;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(onion_key);
  tor_assert(rendezvous_cookie);
  tor_assert(client_pk);

  circ_needs_uptime = hs_service_requires_uptime_circ(service->config.ports);
  /* Help predict this next time */
  rep_hist_note_used_internal(time(NULL), circ_needs_uptime, 1);

  /* Get the extend info data structure for the chosen rendezvous point
   * specified by the given link specifiers. */
  info = get_rp_extend_info(ip->base.link_specifiers, onion_key,
                            service->config.is_single_onion);
  if (info == NULL) {
    /* We are done here, we can't extend to the rendezvous point. */
    goto end;
  }

  for (int i = 0; i < MAX_REND_FAILURES; i++) {
    int circ_flags = CIRCLAUNCH_NEED_CAPACITY | CIRCLAUNCH_IS_INTERNAL;
    if (circ_needs_uptime) {
      circ_flags |= CIRCLAUNCH_NEED_UPTIME;
    }
    /* Firewall and policies are checked when getting the extend info. */
    if (service->config.is_single_onion) {
      circ_flags |= CIRCLAUNCH_ONEHOP_TUNNEL;
    }

    circ = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_CONNECT_REND, info,
                                         circ_flags);
    if (circ != NULL) {
      /* Stop retrying, we have a circuit! */
      break;
    }
  }
  if (circ == NULL) {
    log_warn(LD_REND, "Giving up on launching rendezvous circuit to %s "
                      "for service %s",
             safe_str_client(extend_info_describe(info)),
             safe_str_client(service->onion_address));
    goto end;
  }
  log_info(LD_REND, "Rendezvous circuit launched to %s with cookie %s "
                    "for service %s",
           safe_str_client(extend_info_describe(info)),
           safe_str_client(hex_str((const char *) rendezvous_cookie,
                                   REND_COOKIE_LEN)),
           safe_str_client(service->onion_address));
  tor_assert(circ->build_state);

  /* Create circuit identifier and key material. */
  {
    hs_ntor_rend_cell_keys_t keys;
    curve25519_keypair_t ephemeral_kp;
    /* No need for extra strong, this is only for this circuit life time. This
     * key will be used for the RENDEZVOUS1 cell that will be sent on the
     * circuit once opened. */
    curve25519_keypair_generate(&ephemeral_kp, 0);
    if (hs_ntor_service_get_rendezvous1_keys(&ip->auth_key_kp.pubkey,
                                             &ip->enc_key_kp,
                                             &ephemeral_kp, client_pk,
                                             &keys) < 0) {
      log_info(LD_REND, "Unable to get RENDEZVOUS1 key material for "
                        "service %s",
               safe_str_client(service->onion_address));
      goto end;
    }
    circ->hs_ident = create_rp_circuit_identifier(service, rendezvous_cookie,
                                                  &ephemeral_kp.pubkey, &keys);
    memwipe(&ephemeral_kp, 0, sizeof(ephemeral_kp));
    memwipe(&keys, 0, sizeof(keys));
    tor_assert(circ->hs_ident);
  }

 end:
  extend_info_free(info);
}

/* ========== */
/* Public API */
/* ========== */

/* For a given service and a service intro point, launch a circuit to the
 * extend info ei. If the service is a single onion, a one-hop circuit will be
 * requested. Return 0 if the circuit was successfully launched and tagged
 * with the correct identifier. On error, a negative value is returned. */
int
hs_circ_launch_intro_point(hs_service_t *service,
                           const hs_service_intro_point_t *ip,
                           extend_info_t *ei, time_t now)
{
  /* Standard flags for introduction circuit. */
  int ret = -1, circ_flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  origin_circuit_t *circ;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(ei);

  /* Update circuit flags in case of a single onion service that requires a
   * direct connection. */
  if (service->config.is_single_onion) {
    circ_flags |= CIRCLAUNCH_ONEHOP_TUNNEL;
  }

  log_info(LD_REND, "Launching a circuit to intro point %s for service %s.",
           safe_str_client(extend_info_describe(ei)),
           safe_str_client(service->onion_address));

  /* Note down that we are about to use an internal circuit. */
  rep_hist_note_used_internal(now, circ_flags & CIRCLAUNCH_NEED_UPTIME,
                              circ_flags & CIRCLAUNCH_NEED_CAPACITY);

  /* Note down the launch for the retry period. Even if the circuit fails to
   * be launched, we still want to respect the retry period to avoid stress on
   * the circuit subsystem. */
  service->state.num_intro_circ_launched++;
  circ = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                                       ei, circ_flags);
  if (circ == NULL) {
    goto end;
  }

  /* Setup the circuit identifier and attach it to it. */
  circ->hs_ident = create_intro_circuit_identifier(service, ip);
  tor_assert(circ->hs_ident);

  /* Success. */
  ret = 0;
 end:
  return ret;
}

/* Called when a service introduction point circuit is done building. Given
 * the service and intro point object, this function will send the
 * ESTABLISH_INTRO cell on the circuit. Return 0 on success. Return 1 if the
 * circuit has been repurposed to General because we already have too many
 * opened. */
int
hs_circ_service_intro_has_opened(hs_service_t *service,
                                 hs_service_intro_point_t *ip,
                                 origin_circuit_t *circ)
{
  int ret = 0;
  unsigned int num_intro_circ;

  tor_assert(service);
  tor_assert(ip);
  tor_assert(circ);

  num_intro_circ = count_opened_intro_point_circuits(service);
  if (num_intro_circ > service->config.num_intro_points) {
    /* There are too many opened valid intro circuit for what the service
     * needs so repurpose this one. */

    /* XXX: Legacy code checks options->ExcludeNodes and if not NULL it just
     * closes the circuit. I have NO idea why it does that so it hasn't been
     * added here. --dgoulet */

    log_info(LD_CIRC | LD_REND, "Introduction circuit just opened but we "
                                "have enough for service %s. Repurposing "
                                "it to general and leaving internal.",
             safe_str_client(service->onion_address));
    tor_assert(circ->build_state->is_internal);
    /* Cleaning up the hidden service identifier and repurposing. */
    tor_free(circ->hs_ident);
    circ->hs_ident = NULL;
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_C_GENERAL);
    /* Inform that this circuit just opened for this new purpose. */
    circuit_has_opened(circ);
    /* This return value indicate to the caller that the IP object should be
     * removed from the service because it's corresponding circuit has just
     * been repurposed. */
    ret = 1;
    goto done;
  }

  log_info(LD_REND, "Introduction circuit %u established for service %s.",
           TO_CIRCUIT(circ)->n_circ_id,
           safe_str_client(service->onion_address));
  circuit_log_path(LOG_INFO, LD_REND, circ);

  /* Time to send an ESTABLISH_INTRO cell on this circuit. On error, this call
   * makes sure the circuit gets closed. */
  send_establish_intro(service, ip, circ);

 done:
  return ret;
}

/* Called when a service rendezvous point circuit is done building. Given the
 * service and the circuit, this function will send a RENDEZVOUS1 cell on the
 * circuit using the information in the circuit identifier. If the cell can't
 * be sent, the circuit is closed. */
void
hs_circ_service_rp_has_opened(const hs_service_t *service,
                              origin_circuit_t *circ)
{
  size_t payload_len;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};

  tor_assert(service);
  tor_assert(circ);
  tor_assert(circ->hs_ident);

  /* Some useful logging. */
  log_info(LD_REND, "Rendezvous circuit %u has opened with cookie %s "
                    "for service %s",
           TO_CIRCUIT(circ)->n_circ_id,
           hex_str((const char *) circ->hs_ident->rendezvous_cookie,
                   REND_COOKIE_LEN),
           safe_str_client(service->onion_address));
  circuit_log_path(LOG_INFO, LD_REND, circ);

  /* This can't fail. */
  payload_len = hs_cell_build_rendezvous1(
                        circ->hs_ident->rendezvous_cookie,
                        sizeof(circ->hs_ident->rendezvous_cookie),
                        circ->hs_ident->rendezvous_handshake_info,
                        sizeof(circ->hs_ident->rendezvous_handshake_info),
                        payload);

  if (relay_send_command_from_edge(CONTROL_CELL_ID, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_RENDEZVOUS1,
                                   (const char *) payload, payload_len,
                                   circ->cpath->prev) < 0) {
    /* On error, circuit is closed. */
    log_warn(LD_REND, "Unable to send RENDEZVOUS1 cell on circuit %u "
                      "for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto done;
  }
  /* Change the circuit purpose. */
  circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_S_REND_JOINED);

 done:
  memwipe(payload, 0, sizeof(payload));
}

/* Handle an INTRO_ESTABLISHED cell payload of length payload_len arriving on
 * the given introduction circuit circ and the intro point object ip. The
 * service is only used for logging purposes. Return 0 on success else a
 * negative value.  */
int
hs_circ_handle_intro_established(const hs_service_t *service,
                                 origin_circuit_t *circ,
                                 hs_service_intro_point_t *ip,
                                 const uint8_t *payload, size_t payload_len)
{
  int ret = -1;

  tor_assert(service);
  tor_assert(circ);
  tor_assert(ip);
  tor_assert(payload);

  /* Try to parse the payload into a cell making sure we do actually have a
   * valid cell. */
  if (hs_cell_parse_intro_established(payload, payload_len) < 0) {
    log_warn(LD_REND, "Unable to parse the INTRO_ESTABLISHED cell on "
                      "circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto done;
  }

  /* We do have a valid INTRO_ESTABLISHED cell on this intro point, mark the
   * circuit as established and thus ready to be used in the descriptor. */
  ip->circuit_established = 1;
  /* Switch the purpose to a fully working intro point. */
  circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_S_INTRO);
  /* Getting a valid INTRODUCE_ESTABLISHED means we've successfully used the
   * circuit so update our pathbias subsystem. */
  pathbias_mark_use_success(circ);
  /* Success. */
  ret = 0;

 done:
  return ret;
}

/* Handle an INTRODUCE2 unparsed payload of payload_len for the given circuit
 * and service. This cell is associated with the intro point object ip and the
 * subcredential. Return 0 on success else a negative value. */
int
hs_circ_handle_introduce2(const hs_service_t *service,
                          const origin_circuit_t *circ,
                          hs_service_intro_point_t *ip,
                          const uint8_t *subcredential,
                          const uint8_t *payload, size_t payload_len)
{
  int ret = -1;
  hs_cell_introduce2_data_t data =  {0};

  tor_assert(service);
  tor_assert(circ);
  tor_assert(ip);
  tor_assert(subcredential);
  tor_assert(payload);

  /* Populate the data structure with everything we need for the cell to be
   * parsed, decrypted and key material computed correctly. */
  data.auth_pk = &ip->auth_key_kp.pubkey;
  data.enc_kp = &ip->enc_key_kp;
  data.subcredential = subcredential;
  data.payload = payload;
  data.payload_len = payload_len;
  data.is_legacy = ip->base.is_only_legacy;
  data.replay_cache = ip->replay_cache;

  if (hs_cell_parse_introduce2(&data, circ, service) < 0) {
    goto done;
  }

  /* At this point, we just confirmed that the full INTRODUCE2 cell is valid
   * so increment our counter that we've seen one on this intro point. */
  ip->introduce2_count++;

  /* Launch rendezvous circuit with the onion key and rend cookie. */
  launch_rendezvous_point_circuit(service, ip, &data.onion_pk,
                                  data.rendezvous_cookie, &data.client_pk);
  /* Success. */
  ret = 0;

 done:
  memwipe(&data, 0, sizeof(data));
  return ret;
}

/* Free the given circuit identifier. */
void
hs_circ_identifier_free(hs_circ_identifier_t *ident)
{
  if (ident == NULL) {
    return;
  }
  if (ident->auth_key_type == HS_AUTH_KEY_TYPE_LEGACY) {
    crypto_pk_free(ident->intro_key.legacy);
  }
  tor_free(ident);
}

