/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service functionality
 **/

#define HS_CONFIG_PRIVATE

#include "hs_common.h"
#include "hs_config.h"
#include "hs_service.h"
#include "rendservice.h"

/* Configureation handler for a version 3 service. Return 0 on success else a
 * negative value. */
static int
config_service_v3(const config_line_t *line,
                  const or_options_t *options, int validate_only,
                  hs_service_t *service)
{
  (void) line;
  (void) service;
  (void) validate_only;
  (void) options;
  /* XXX: Configure a v3 service with specific options. */
  /* XXX: Add service to v3 list and pruning on reload. */
  return 0;
}

/* Configure a service using the given options in line_ and options. This is
 * called for every version of a service which means that all directives in
 * this function are generic to all services. This function will also check
 * the validity of the service directory path. Return 0 on success else -1. */
static int
config_generic_service(const config_line_t *line_,
                       const or_options_t *options,
                       hs_service_t *service)
{
  int ok, dir_seen = 0;
  const config_line_t *line;
  hs_service_config_t *config;

  tor_assert(line_);
  tor_assert(options);
  tor_assert(service);

  /* Makes thing easier. */
  config = &service->config;

  /* The first line starts with HiddenServiceDir so we consider what's next is
   * the configuration of the service. */
  for (line = line_; line ; line = line->next) {
    /* This indicate that we have a new service to configure. */
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      /* This function only configures one service at a time so if we've
       * already seen one, stop right now. */
      if (dir_seen) {
        break;
      }
      /* Ok, we've seen one and we are about to configure it. */
      dir_seen = 1;
      config->directory_path = tor_strdup(line->value);
      continue;
    }
    /* Version of the service. */
    if (!strcasecmp(line->key, "HiddenServiceVersion")) {
      service->version = (uint32_t) tor_parse_ulong(line->value,
                                                    10, HS_VERSION_TWO,
                                                    HS_VERSION_MAX,
                                                    &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceVersion be between %u and %u, not %s",
                 HS_VERSION_TWO, HS_VERSION_MAX, line->value);
        goto err;
      }
      log_info(LD_CONFIG, "HiddenServiceVersion=%" PRIu32 " for %s",
               service->version, escaped(config->directory_path));
      continue;
    }
    /* Virtual port. */
    if (!strcasecmp(line->key, "HiddenServicePort")) {
      char *err_msg = NULL;
      /* XXX: Can we rename this? */
      rend_service_port_config_t *portcfg =
        rend_service_parse_port_config(line->value, " ", &err_msg);
      if (!portcfg) {
        if (err_msg) {
          log_warn(LD_CONFIG, "%s", err_msg);
        }
        tor_free(err_msg);
        goto err;
      }
      tor_assert(!err_msg);
      smartlist_add(config->ports, portcfg);
      continue;
    }
    /* Do we allow unknown ports. */
    if (!strcasecmp(line->key, "HiddenServiceAllowUnknownPorts")) {
      config->allow_unknown_ports = (unsigned int) tor_parse_long(line->value,
                                                                  10, 0, 1,
                                                                  &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceAllowUnknownPorts should be 0 or 1, not %s",
                 line->value);
        goto err;
      }
      log_info(LD_CONFIG,
               "HiddenServiceAllowUnknownPorts=%u for %s",
               config->allow_unknown_ports, escaped(config->directory_path));
      continue;
    }
    /* Directory group readable. */
    if (!strcasecmp(line->key, "HiddenServiceDirGroupReadable")) {
      config->dir_group_readable = (unsigned int) tor_parse_long(line->value,
                                                                 10, 0, 1,
                                                                 &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceDirGroupReadable should be 0 or 1, not %s",
                 line->value);
        goto err;
      }
      log_info(LD_CONFIG,
               "HiddenServiceDirGroupReadable=%u for %s",
               config->dir_group_readable, escaped(config->directory_path));
      continue;
    }
    /* Maximum streams per circuit. */
    if (!strcasecmp(line->key, "HiddenServiceMaxStreams")) {
      config->max_streams_per_rdv_circuit = tor_parse_uint64(line->value,
                                                             10, 0, 65535,
                                                             &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceMaxStreams should be between 0 and %d, not %s",
                 65535, line->value);
        goto err;
      }
      log_info(LD_CONFIG,
               "HiddenServiceMaxStreams=%" PRIu64 " for %s",
               config->max_streams_per_rdv_circuit,
               escaped(config->directory_path));
      continue;
    }
    /* Maximum amount of streams before we close the circuit. */
    if (!strcasecmp(line->key, "HiddenServiceMaxStreamsCloseCircuit")) {
      config->max_streams_close_circuit =
        (unsigned int) tor_parse_long(line->value, 10, 0, 1, &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceMaxStreamsCloseCircuit should be 0 or 1, "
                 "not %s", line->value);
        goto err;
      }
      log_info(LD_CONFIG,
               "HiddenServiceMaxStreamsCloseCircuit=%u for %s",
               config->max_streams_close_circuit,
               escaped(config->directory_path));
      continue;
    }
  }

  /* Check permission on service directory. */
  if (hs_check_service_private_dir(options->User, config->directory_path,
                                   config->dir_group_readable, 0) < 0) {
    goto err;
  }

  /* Success */
  return 0;
 err:
  return -1;
}

/* Configuration handler indexed by version number. */
static int
  (*config_service_handlers[])(const config_line_t *line,
                               const or_options_t *options,
                               int validate_only,
                               hs_service_t *service) =
{
  NULL, /* v0 */
  NULL, /* v1 */
  rend_config_service, /* v2 */
  config_service_v3, /* v3 */
};

/* From a set of <b>options</b>, setup every hidden service found. Return 0 on
 * success or -1 on failure. If <b>validate_only</b> is set, parse, warn and
 * return as normal, but don't actually change the configured services. */
int
hs_config_service_all(const or_options_t *options, int validate_only)
{
  int dir_option_seen = 0;
  hs_service_t *service = NULL;
  const config_line_t *line;

  tor_assert(options);

  for (line = options->RendConfigLines; line; line = line->next) {
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      /* We have a new hidden service. */
      service = hs_service_new(options);
      /* We'll configure that service as a generic one and then pass it to the
       * specific handler according to the configured version number. */
      if (config_generic_service(line, options, service) < 0) {
        goto err;
      }
      tor_assert(service->version <= HS_VERSION_MAX);
      /* The handler is in charge of specific options for a version. We start
       * after this service directory line so once we hit another directory
       * line, the handler knows that it has to stop. */
      if (config_service_handlers[service->version](line->next, options,
                                                    validate_only,
                                                    service) < 0) {
        goto err;
      }
      /* Whatever happens, on success we loose the ownership of the service
       * object so we nullify the pointer to be safe. */
      service = NULL;
      /* Flag that we've seen a directory directive and we'll use that to make
       * sure that the torrc options ordering are actually valid. */
      dir_option_seen = 1;
      continue;
    }
    /* The first line must be a directory option else tor is misconfigured. */
    if (!dir_option_seen) {
      log_warn(LD_CONFIG, "%s with no preceding HiddenServiceDir directive",
               line->key);
      goto err;
    }
  }

  if (!validate_only) {
    /* Trigger service pruning which will make sure the just configured
     * services end up in the main global list. This is v2 specific. */
    rend_service_prune_list();
    /* XXX: Need the v3 one. */
  }

  /* Success. */
  return 0;
 err:
  hs_service_free(service);
  /* Tor main should call the free all function. */
  return -1;
}

