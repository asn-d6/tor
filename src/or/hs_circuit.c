/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 **/

#include "or.h"
#include "circuitbuild.h"
#include "circuituse.h"
#include "config.h"
#include "rephist.h"
#include "router.h"

#include "hs_circuit.h"
#include "hs_service.h"

/* Trunnel. */
#include "hs/cell_common.h"

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

