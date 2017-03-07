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
#include "relay.h"
#include "rephist.h"
#include "router.h"

#include "hs_cell.h"
#include "hs_circuit.h"
#include "hs_service.h"

/* Trunnel. */
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

/* ========== */
/* Public API */
/* ========== */

int
hs_circ_launch_rendezvous_point(const hs_service_t *service,
                                const curve25519_public_key_t *onion_key,
                                const uint8_t *rendezvous_cookie)
{
  tor_assert(service);
  tor_assert(onion_key);
  tor_assert(rendezvous_cookie);
  /* XXX: Implement rendezvous launch support. */
  return 0;
}

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

  if (hs_cell_parse_introduce2(&data, circ, service) < 0) {
    goto done;
  }

  /* At this point, we just confirmed that the full INTRODUCE2 cell is valid
   * so increment our counter that we've seen one on this intro point. */
  ip->introduce2_count++;

  /* Launch rendezvous circuit with the onion key and rend cookie. */
  ret = hs_circ_launch_rendezvous_point(service, &data.onion_pk,
                                        data.rendezvous_cookie);
  if (ret < 0) {
    goto done;
  }

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

