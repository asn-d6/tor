/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DOS_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#define CIRCUITLIST_PRIVATE

#include "or.h"
#include "dos.h"
#include "circuitlist.h"
#include "geoip.h"
#include "channel.h"
#include "test.h"
#include "log_test_helpers.h"

static unsigned int
mock_enable_dos_protection(void)
{
  return 1;
}

/** Test that the connection tracker of the DoS subsystem will block clients
 *  who try to establish too many connections */
static void
test_dos_conn_creation(void *arg)
{
  (void) arg;

  MOCK(get_ns_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_ns_param_conn_enabled, mock_enable_dos_protection);

  /* Initialize test data */
  tor_addr_t addr;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&addr, "18.0.0.1"));

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_concurrent_conns = get_ns_param_conn_max_concurrent_count();

  /* Introduce new client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  { /* Register many conns from this client but not enough to get it blocked */
    unsigned int i;
    for (i = 0; i < max_concurrent_conns; i++) {
      dos_new_client_conn(&addr);
    }
  }

  /* Check that new conns are still permitted */
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(&addr));

  /* Register another conn and check that new conns are not allowed anymore */
  dos_new_client_conn(&addr);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(&addr));

  /* Close a client conn and see that a new conn will be permitted again */
  dos_close_client_conn(&addr);
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(&addr));

  /* Register another conn and see that defense measures get reactivated */
  dos_new_client_conn(&addr);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(&addr));

 done:
  dos_free_all();
}

/** Helper mock: Place a fake IP addr for this channel in <b>addr_out</b> */
static int
mock_channel_get_addr_if_possible(channel_t *chan, tor_addr_t *addr_out)
{
  (void)chan;
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(addr_out, "18.0.0.1"));;
  return 1;

 done:
  return 0;
}

/** Test that the circuit tracker of the DoS subsystem will block clients who
 *  try to establish too many circuits. */
static void
test_dos_circuit_creation(void *arg)
{
  (void) arg;
  unsigned int i;

  MOCK(get_ns_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_ns_param_conn_enabled, mock_enable_dos_protection);
  MOCK(channel_get_addr_if_possible,
       mock_channel_get_addr_if_possible);

  /* Initialize channels/conns/circs that will be used */
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->is_client = 1;

  /* Initialize test data */
  tor_addr_t addr;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&addr, "18.0.0.1"));

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_circuit_count = get_ns_param_cc_circuit_max_count();
  uint32_t min_conc_conns_for_cc = get_ns_param_cc_min_concurrent_connection();

  /* Introduce new client and establish enough connections to activate the
   * circuit counting subsystem */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, NULL, now);
  for (i = 0; i < min_conc_conns_for_cc ; i++) {
    dos_new_client_conn(&addr);
  }

  /* Register new circuits for this client and conn, but not enough to get
   * detected as dos */
  for (i=0; i < max_circuit_count-1; i++) {
    dos_cc_new_create_cell(chan);
  }
  /* see that we didn't get detected for dosing */
  tt_int_op(DOS_CC_DEFENSE_NONE, OP_EQ, dos_cc_get_defense_type(chan));

  /* Register another CREATE cell that will push us over the limit. Check that
   * the cell gets refused. */
  dos_cc_new_create_cell(chan);
  tt_int_op(DOS_CC_DEFENSE_REFUSE_CELL, OP_EQ, dos_cc_get_defense_type(chan));

  /* TODO: Wait a few seconds before sending the cell, and check that the
     buckets got refilled properly. */
  /* TODO: Actually send a Tor cell (instead of calling the DoS function) and
   * check that it will get refused */

 done:
  tor_free(chan);
  dos_free_all();
}

struct testcase_t dos_tests[] = {
  { "conn_creation", test_dos_conn_creation, TT_FORK,
    NULL, NULL },
  { "circuit_creation", test_dos_circuit_creation, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

