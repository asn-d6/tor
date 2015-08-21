
/*  This is some pseudocode of a new algorithm for picking entry guards.
 *
 *  The meat here is get_entry_guard() which tries to return the top entry guard
 *  that is available for use by this circuit.
 *
 *  It first checks that we have not attempted too many guards lately
 *  (prop241).
 *
 *  Then, if the top guards on our list are marked offline, the algorithm
 *  attempts to retry them, to ensure that they were not flagged offline
 *  erroneously when the network was down. This retry attempt happens only
 *  once every 20 mins to avoid infinite loops.
 *
 *  Finally, the algorithm takes the list of all available and fitting entry
 *  guards, and returns the top one in the list.
 *
 *  If there were no available entry guards, the algorithm adds a new entry
 *  guard and returns it.
 *
 *  In this file, we start by defining our parameters and utility methods, and
 *  in the end we define the get_entry_guard() function.
 */

/****************************************************************************/


/* This threshold limits the amount of guards we will attempt to connect to. If
   this threshold is hit we assume that we are offline, or filtered or under a
   path bias attack by a LAN adversary.

   There are currently 1600 guards in the network. We allow the user to attempt
   80 of them before failing (5% of the guards). With regards to filternet
   reachability, there are 450 guards on ports 80 or 443, so the probability of
   picking such a guard guard here should be high.

   It would be smarter if this logic was done based on bandwidth and not on the
   number of relays, but that would be harder to implement and might lead to
   weird attacks. Think more! */
GUARDS_ATTEMPTED_THRESHOLD = 80; /* This should be a consensus parameter. */

/* We consider the first active PRIMARY_GUARDS on our list as "primary". We will
   go to extra lengths to ensure that we connect to one of our primary guards,
   before we fall back to a lower priority guard. By "active" we mean that we
   only consider guards that are present in the latest consensus as primary. */
PRIMARY_GUARDS = 3; /* This should be a consensus parameter.

struct guard_list_t {
  /* An ordered list of guards. */
  smartlist_t guard_list;

  /* The number of distinct entry guards we attempted to connect to
     lately. This counter is tied to a 5 days reset timer.

     Implementation note: Some sort of lookup table will be needed to
     ensure that only unique entry guards are counted here. */
  int n_guards_attempted_lately = 0;

  /* Whether we have probed unreachable primary guards lately. This is
     tied to a 20 minutes reset timer. (XXX smaller reset timer?) */
  bool retried_primary_guards = False;
} guard_list_t;

def guard_is_primary(entry_guard_t) {
  /* Returns True if this guard is one of the top PRIMARY_GUARDS and is also
     present on the latest consensus. */
}

def primary_guards_are_unreachable(guard_list_t) {
  /* Returns True if the top PRIMARY_GUARDS on the guard list are unreachable
     but still present as a guard on the latest consensus. */
}

def guards_mark_all_for_retry() {
  /* Like the current entries_retry_all().

     XXX Should this also mark relays that are not in the consensus for
     retry? Probs not.
  */
}

def primary_guards_mark_all_for_retry() {
  /* Like entries_retry_all() but only toggle the primary guards as retriable */
}

def guard_is_down() {
  /* Called when a guard should be marked as offline.
     See entry_guard_register_connect_status() */

  /* The big question here is when should this be called? Is dropping
     a single CREATE cell sufficient reason to mark the top primary
     guard as offline? */
}

def connected_to_guard() {
  /* We managed to connect to a guard successfully!
     According to prop241, this should be called when we finish authenticating its
     identity. Also see entry_guard_register_connect_status().
  */

  /* This function should also walk the guard list, and remove any guards that
     we have never managed to connect to. This will clean the guard list, which
     might be dirty from all the nodes that we attempted during a network down
     event. This is done so that the whole guard list does not get filled the
     first time that Tor is left without network. This is also more similar to
     the current behavior of Tor. XXX should we do this? */
}

def add_an_entry_guard(guard_list_t, circuit_t) {
  /* Adds a new entry guard to the guard list according to the needs of the
     circuit. If it's a directory circuit, we need a dirguard. */
}

def update_guard_list_with_new_consensus(guard_list_t) {
  /* We just received a new consensus. If some of our guards are not online or
     guards anymore, update our guard list by marking them as bad.
     See entry_guards_compute_status(). */
}

/* This function returns the guard that should be used for this
   circuit. It's a replacement for choose_random_entry(). */
int get_entry_guard(circuit_t) {
  if (guard_list.n_guards_attempted_lately > GUARDS_ATTEMPTED_THRESHOLD) {
    /* We have attempted to connect to many guards and they don't work. The
       network might be down, a captive portal might be on, or we might be under
       attack. Instead of trying more guards, flag the old ones for retry. */
    guards_mark_all_for_retry();
    guard_list.n_guards_attempted_lately = 0;
  }

  if (smartlist_len(guard_list) &&
      primary_guards_are_unreachable(guard_list) &&
      !guard_list.retried_primary_guards) {
    /* If our primary guards are unreachable, make sure we retry them at least
       once a while before using any lower priority guards. By doing this we try
       to avoid edge cases where the network was down but came back up before
       hitting one of the thresholds above. */
    primary_guards_mark_all_for_retry();
    guard_list.retried_primary_guards = True;
  }

  /* Filter the list of guards and find the ones that are not offline and also
     have the right flags/bw/dirinfo for this circuit. */
  live_entry_guards = populate_live_entry_guards(guard_list_t, circuit_t);

  /* If we are out of available entry guards, add a new one. */
  if (!live_entry_guards) {
    retval = add_an_entry_guard(guard_list_t, circuit_t);
    live_entry_guards = populate_live_entry_guards(guard_list_t, circuit_t);
  }

  /* There must be at least one guard here now. */
  assert(live_entry_guards);

  /* Return the first available fitting guard */
  first_live_guard = live_entry_guards[0];
  return first_live_guard;

  /* The attempted counter will be increased by the caller of this function,
     when it actually tries to connect to the guard. */
}
