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

/* Using the given list of services, stage them into our global state. Every
 * service version are handled. */
static void
stage_services(smartlist_t *service_list)
{
  tor_assert(service_list);

  /* This is v2 specific. Trigger service pruning which will make sure the
   * just configured services end up in the main global list. It should only
   * be done in non validation mode because v2 subsystem handles service
   * object differently. */
  rend_service_prune_list();

  /* Cleanup v2 service from the list, we don't need those object anymore
   * because we validated them all against the others and we want to stage
   * only >= v3 service. And remember, v2 has a different object type which is
   * shadow copied from an hs_service_t type. */
  SMARTLIST_FOREACH_BEGIN(service_list, hs_service_t *, s) {
    if (s->version == HS_VERSION_TWO) {
      SMARTLIST_DEL_CURRENT(service_list, s);
      hs_service_free(s);
    }
  } SMARTLIST_FOREACH_END(s);

  /* This is >= v3 specific. Using the newly configured service list, stage
   * them into our global state. Every object ownership is lost after. */
  hs_service_stage_services(service_list);
}

/* Validate the given service against all service in the given list. If the
 * service is ephemeral, this function ignores it. Services with the same
 * directory path aren't allowed and will return an error. On success, 0 is
 * returned else a negative value if service is invalid. */
static int
validate_service_list(smartlist_t *service_list, hs_service_t *service)
{
  int ret = 0;

  tor_assert(service_list);
  tor_assert(service);

  /* Ephemeral service don't have a directory configured so no need to check
   * for a service in the list having the same path. */
  if (service->config.is_ephemeral) {
    goto end;
  }

  /* XXX: Validate if we have any service that has the given service dir path.
   * This has two problems:
   *
   * a) It's O(n^2), but the same comment from the bottom of
   *    rend_config_services() should apply.
   *
   * b) We only compare directory paths as strings, so we can't
   *    detect two distinct paths that specify the same directory
   *    (which can arise from symlinks, case-insensitivity, bind
   *    mounts, etc.).
   *
   * It also can't detect that two separate Tor instances are trying
   * to use the same HiddenServiceDir; for that, we would need a
   * lock file.  But this is enough to detect a simple mistake that
   * at least one person has actually made. */
  SMARTLIST_FOREACH_BEGIN(service_list, hs_service_t *, s) {
    if (!strcmp(s->config.directory_path, service->config.directory_path)) {
      log_warn(LD_REND, "Another hidden service is already configured "
                        "for directory %s",
               escaped(service->config.directory_path));
      ret = -1;
      goto end;
    }
  } SMARTLIST_FOREACH_END(s);

 end:
  return ret;
}

/* Validate service configuration. This is used when loading the configuration
 * and once we've setup a service object, it's config object is passed to this
 * function for further validation. This does not validate service key
 * material. Return 0 if valid else -1 if invalid. */
static int
config_validate_service(const hs_service_config_t *config)
{
  tor_assert(config);

  /* Amount of ports validation. */
  if (!config->ports || smartlist_len(config->ports) == 0) {
    log_warn(LD_CONFIG, "Hidden service (%s) with no ports configured.",
             escaped(config->directory_path));
    goto invalid;
  }

  /* Valid. */
  return 0;
 invalid:
  return -1;
}

/* Configureation handler for a version 3 service. Return 0 on success else a
 * negative value. */
static int
config_service_v3(const config_line_t *line_,
                  const or_options_t *options,
                  hs_service_t *service)
{
  (void) options;
  const config_line_t *line;
  hs_service_config_t *config;

  tor_assert(service);

  config = &service->config;

  for (line = line_; line; line = line->next) {
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      /* We just hit the next hidden service, stop right now. */
      break;
    }
    /* Number of introduction points. */
    if (!strcasecmp(line->key, "HiddenServiceNumIntroductionPoints")) {
      int ok = 0;
      config->num_intro_points =
        (unsigned int) tor_parse_ulong(line->value, 10,
                                       NUM_INTRO_POINTS_DEFAULT,
                                       HS_CONFIG_V3_MAX_INTRO_POINTS,
                                       &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG, "HiddenServiceNumIntroductionPoints "
                 "should be between %d and %d, not %s",
                 NUM_INTRO_POINTS_DEFAULT, HS_CONFIG_V3_MAX_INTRO_POINTS,
                 line->value);
        goto err;
      }
      log_info(LD_CONFIG, "HiddenServiceNumIntroductionPoints=%d for %s",
               config->num_intro_points, escaped(config->directory_path));
      continue;
    }
  }

  /* We do not load the key material for the service at this stage. This is
   * done later once tor can confirm that it is in a running state. */

  /* We are about to return a fully configured service so do one last pass of
   * validation at it. */
  if (config_validate_service(config) < 0) {
    goto err;
  }

  return 0;
 err:
  return -1;
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
                                                    10, HS_VERSION_MIN,
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
      config->max_streams_per_rdv_circuit =
        tor_parse_uint64(line->value, 10, 0,
                         HS_CONFIG_MAX_STREAMS_PER_RDV_CIRCUIT, &ok, NULL);
      if (!ok) {
        log_warn(LD_CONFIG,
                 "HiddenServiceMaxStreams should be between 0 and %d, not %s",
                 HS_CONFIG_MAX_STREAMS_PER_RDV_CIRCUIT, line->value);
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
                               hs_service_t *service) =
{
  NULL, /* v0 */
  NULL, /* v1 */
  rend_config_service, /* v2 */
  config_service_v3, /* v3 */
};

/* Configure a service using the given line and options. This function will
 * call the corresponding version handler and validate the service against the
 * other one. On success, add the service to the given list and return 0. On
 * error, nothing is added to the list and a negative value is returned. */
static int
config_service(const config_line_t *line, const or_options_t *options,
               smartlist_t *service_list)
{
  hs_service_t *service = NULL;

  tor_assert(line);
  tor_assert(options);
  tor_assert(service_list);

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
                                                service) < 0) {
    goto err;
  }
  /* We'll check if this service can be kept depending on the others
   * configured previously. */
  if (validate_service_list(service_list, service) < 0) {
    goto err;
  }
  /* Passes, add it to the given list. */
  smartlist_add(service_list, service);
  return 0;

 err:
  hs_service_free(service);
  return -1;
}

/* From a set of <b>options</b>, setup every hidden service found. Return 0 on
 * success or -1 on failure. If <b>validate_only</b> is set, parse, warn and
 * return as normal, but don't actually change the configured services. */
int
hs_config_service_all(const or_options_t *options, int validate_only)
{
  int dir_option_seen = 0, ret = -1;
  const config_line_t *line;
  smartlist_t *new_service_list = NULL;

  tor_assert(options);

  /* Newly configured service are put in that list which is then used for
   * validation and staging for >= v3. */
  new_service_list = smartlist_new();

  for (line = options->RendConfigLines; line; line = line->next) {
    /* Ignore all directives that aren't the start of a service. */
    if (strcasecmp(line->key, "HiddenServiceDir")) {
      if (!dir_option_seen) {
        log_warn(LD_CONFIG, "%s with no preceding HiddenServiceDir directive",
                 line->key);
        goto err;
      }
      continue;
    }
    /* Flag that we've seen a directory directive and we'll use it to make
     * sure that the torrc options ordering is actually valid. */
    dir_option_seen = 1;

    /* Try to configure this service now. On success, it will be added to the
     * list and validated against the service in that same list. */
    if (config_service(line, options, new_service_list) < 0) {
      goto err;
    }
  }

  /* In non validation mode, we'll stage those services we just successfully
   * configured. Service ownership is transfered from the list to the global
   * state. If any service is invalid, it will be removed from the list and
   * freed. All versions are handled in that function. */
  if (!validate_only) {
    stage_services(new_service_list);
  } else {
    /* We've just validated that we were able to build a clean working list of
     * services. We don't need those objects anymore. */
    SMARTLIST_FOREACH(new_service_list, hs_service_t *, s,
                      hs_service_free(s));
  }

  /* Success. Note that the service list has no ownership of its content. */
  ret = 0;
  goto end;

 err:
  SMARTLIST_FOREACH(new_service_list, hs_service_t *, s, hs_service_free(s));

 end:
  smartlist_free(new_service_list);
  /* Tor main should call the free all function on error. */
  return ret;
}

