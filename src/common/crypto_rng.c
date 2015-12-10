/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_rng.c
 * \brief Wrapper functions for cryptographic functions related to
 * random number generation.
 **/

#include "orconfig.h"

#include "compat.h"
#include "crypto.h"
#include "crypto_rng.h"
#include "torlog.h"
#include "util.h"

#include <openssl/engine.h>
#include <openssl/rand.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include "compat_openssl.h"

#include "keccak-tiny/keccak-tiny.h"

#ifndef _WIN32
#define HAVE_PID
#include <unistd.h>
#endif

/* PRNG design:
 *
 * This PRNG is designed to accelerate and (possibly) improve the security
 * of one or more underlying slower PRNGs whose output may or may not be
 * safe to expose.
 *
 * Its operation is simple: it generates a bunch of bytes at once using the
 * SHAKE XOF, using the underlying PRNGs as inputs.  As bytes are yielded
 * to the caller, they are cleared and removed from the buffer.  The first
 * SHAKE output bytes in each buffer after the first are used as an extra
 * input to SHAKE for generating the next.
 *
 * Fast underlying PRNGS are added as input every time the buffer is
 * regenerated; slow underlying PRNGS are used at startup, and when the
 * buffer is reseeded.
 *
 * This PRNG scheme is:
 *   - About as fast as SHAKE.
 *   - Backtracking resistant.
 *   - Prediction resistant after any refresh that uses a prediction-resistant
 *     underlying RNG.
 */


/* Use SHAKE256 */
#define PRNG_SHAKE_BITS ( 256 )

/* Ideal rate to add or remove bytes bytes to avoid needless Keccak-f calls */
#define PRNG_SHAKE_RATE ( KECCAK_RATE(PRNG_SHAKE_BITS) )

/* How many Keccak-f calls do we do per buffer fill? Designed to keep the
 * size under 4096. */
#define PRNG_SHAKE_COUNT 24

/* If this is defined, we replace OpenSSL's default PRNG with the one
 * implemented here.
 */
#undef REPLACE_OPENSSL_RAND

/* If this is defined, we add a lot of assertions to catch problems in the
 * code
 */
#define CHECK_INVARIANTS

/**
 * How many bytes from each SHAKE output should we use as input to the
 * next SHAKE call?
 */
#define PRNG_CARRYFORWARD (PRNG_SHAKE_BITS * 2)

/** Data structure for the SHAKE-based PRNG.
 *
 * This structure should be used as a singleton; the fields are kept in
 * a structure so that we can map them all in an mmap region that we
 * then lock down.
 */
typedef struct shake_prng_t {
#ifdef HAVE_PID
  /**
   * Tracks the pid that has permission to use this structure.
   * Unless we're on windows (where fork doesn't exist) we should check
   * whether we've forked.  Unlike other general-purpose PRNGS, we don't
   * attempt to keep working on a fork; instead we demand that the user call a
   * "postfork" function.
   */
  pid_t pid;
#endif
  /**
   * True iff we are currently reseeding this prng because of elapsed time
   * or having generated too much data since the last reseed.  Used to
   * prevent duplicate reseeds.
   */
  uint8_t reseeding;
  /**
   * How many times have we refilled the buffer since the last reseed?
   */
  uint32_t refill_count;
  /**
   * How many bytes are left for the user in buf?
   * Invariant: we never return to user code with remaining == 0.
   * Invariant: remaining <= sizeof(sh.buf)
   */
  uint16_t remaining;
  /**
   * When did we last reseed the buffer?
   */
  time_t last_reseeded;
  /**
   * What is the next byte in buf that we can yield to the user?
   * Invariant: ptr == buf + sizeof(buf) - remaining
   */
  uint8_t *ptr;
  /**
   * SHAKE output.
   *
   * Invariant: buf[0]...ptr[-1] are all set to 0.
   */
  struct {
    uint8_t carryforward[PRNG_CARRYFORWARD];
    uint8_t buf[PRNG_SHAKE_RATE * PRNG_SHAKE_COUNT - PRNG_CARRYFORWARD];
  } sh;
} shake_prng_t;

/**
 * After how many refills of the buffer should we reseed from the OS prng?
 */
#define PRNG_RESEED_AFTER 1024
/**
 * After how many seconds since the last reseed should we reseed from the
 * OS prng?
 */
#define PRNG_RESEED_AFTER_TIME 3600

/**
 * How many bytes from OpenSSL's RAND_bytes should we use as input to
 * each SHAKE call?
 */
#define PRNG_OPENSSL_BYTES 32
/**
 * When reseeding the PRNG, include this many bytes from the OS RNG.
 */
#define PRNG_OS_BYTES 32
/**
 * If we have a libc-provided fast strong random number generator (eg
 * arc4random) include this many bytes of its output as input to each SHAKE
 * call.
 */
#define PRNG_LIBC_BYTES 64

/** This mutex protects the field the_prng, and all members of the_prng. */
static tor_mutex_t prng_mutex;
/** This field is the singleton prng allocated for Tor. */
static shake_prng_t *the_prng = NULL;

static void shake_prng_reseed(shake_prng_t *prng);
static void shake_prng_refill(shake_prng_t *prng,
                              const uint8_t *seed, size_t n);
static void shake_prng_getbytes(shake_prng_t *prng, uint8_t *out, size_t n);
#ifdef REPLACE_OPENSSL_RAND
static void usurp_openssl_rand_method(void);
#endif
#ifdef CHECK_INVARIANTS
static void shake_prng_test_invariants(const shake_prng_t *prng);
#else
#define shake_prng_test_invariants(prng) do { } while (0)
#endif

/* Allocation functions for our PRNG.  We try to grab about a page or two of
 * RAM, so that we don't have to make too many SHAKE calls.  We also try to
 * use mmapped pages rather than malloc here, so that we can safely
 * use mprotect, minherit, madvise, etc on them.
 */
#ifdef HAVE_SYS_MMAN_H
/**
 * Allocate and return memory for use in a shake PRNG. Set *<b>sz_out</b> to
 * the actual number of bytes allocated.
 */
static void *
new_prng_page(void)
{
  const size_t sz = sizeof(shake_prng_t);
  void *result = mmap(NULL, sz,
                      PROT_READ | PROT_WRITE,
                      MAP_ANON | MAP_PRIVATE,
                      -1, 0);
  tor_assert(result);

  /* XXX Maybe use inherit_zero, inherit_none, madv_dontfork. */

#ifdef MADV_DONTDUMP
  /* Tell the operating system that this memory shouldn't go into coredumps. */
  {
    int r = madvise(result, sz, MADV_DONTDUMP);
    tor_assert(r == 0);
  }
#endif
#ifdef HAVE_MLOCK
  /* Tell the operating system that this memory shouldn't get swapped. */
  {
    int r = mlock(result, sz);
    tor_assert(r == 0);
  }
#endif

  return result;
}
/** Release storage held by <b>page</b>, which must be a return value from
 * new_prng_page.
 */
static void
free_prng_page(void *page)
{
  if (! page)
    return;
  const size_t sz = sizeof(shake_prng_t);
  memwipe(page, 0, sz);
#ifdef HAVE_MLOCK
  munlock(page, sz);
#endif
  munmap(page, sz);
}
#elif defined(_WIN32)
static void *
new_prng_page(void)
{
  const size_t sz = sizeof(shake_prng_t);
  HANDLE mapping = CreateFileMapping(INVALID_HANDLE_VALUE,
                                     NULL, /*attributes*/
                                     PAGE_READWRITE,
                                     0,
                                     sz & 0xffffffff,
                                     NULL /* name */);
  tor_assert(mapping != NULL);
  void *result = MapViewOfFile(mapping, FILE_MAP_WRITE,
                               0, 0, /* Offset */
                               0 /* Extend to end of mapping */);
  tor_assert(result);
  CloseHandle(mapping); /* mapped view holds a reference */

  /* Prevent the RAM From getting swapped out. */
  VirtualLock(result, sz);

  return result;
}

static void
free_prng_page(void *page)
{
  if (!page)
    return;
  const size_t sz = sizeof(shake_prng_t);
  memwipe(page, 0, sz);
  VirtualUnlock(page, sz);
  UnmapViewOfFile(page);
}
#else
static void *
new_prng_page(void)
{
  return tor_malloc_zero(sizeof(shake_prng_t));
}

static void
free_prng_page(void *page)
{
  memwipe(page, 0, sizeof(shake_prng_t));
  tor_free(page);
}
#endif

/**
 * Initialize the SHAKE-based CSPRNG.  This function must be called before
 * extracting any data from the prng, or calling any other function on it.
 *
 * Failure to do so will cause a crash or deadlock.
 */
void
crypto_init_shake_prng(void)
{
  /* Initialize the mutex */
  tor_mutex_init_nonrecursive(&prng_mutex);

  shake_prng_t *prng = new_prng_page();

  /* We're trying to be about one page. */
  tor_assert(sizeof(prng->sh) <= 4096);

  /* Technically, the C compiler is allowed to pad prng->sh for alignment.
   * It shouldn't; nobody reasonable would define alignof(char) to something
   * other than 1.  But let's make sure that the structure is as big as we
   * want.
   */
  tor_assert(sizeof(prng->sh) % PRNG_SHAKE_RATE == 0);

  /* Seed it for the first time... */
  shake_prng_reseed(prng);

  shake_prng_test_invariants(prng);

  /* THEN put it in the static variable. */
  the_prng = prng;

#ifdef REPLACE_OPENSSL_RAND
  usurp_openssl_rand_method();
#endif
}

/**
 * Reseed the PRNG -- that is to say, refill the buffer, including
 * bytes from the operating system strong RNG.
 *
 * The caller MUST NOT hold the mutex.
 */
static void
shake_prng_reseed(shake_prng_t *prng)
{
  uint8_t buf[PRNG_OS_BYTES];

  /* Grab the entropy now, outside of the lock.  This way other threads can
   * keep accessing the PRNG while this call is in progress.
   *
   * (We don't need to worry about threads seeing an unseeded PRNG, since
   * we don't expose it to them till after it's seeded at least once.)
   */
  if (crypto_strongest_rand_raw(buf, PRNG_OS_BYTES)) {
    log_err(LD_CRYPTO, "Couldn't get os entropy to reseed shake prng. Dying.");
    tor_assert(0);
  }

  tor_mutex_acquire(&prng_mutex);
  shake_prng_refill(prng, buf, sizeof(buf));
  /* Mark us as not needing a reseed for a while, and not in the middle of
   * an automated reseed. */
  prng->refill_count = 1;
  prng->reseeding = 0;
  prng->last_reseeded = time(NULL);
  /* We reseeded from the OS, so now we can forget any old pid we were in. */
#ifdef HAVE_PID
  prng->pid = getpid();
#endif
  shake_prng_test_invariants(prng);
  tor_mutex_release(&prng_mutex);

  memwipe(buf, 0, sizeof(buf));
}


#ifdef REPLACE_OPENSSL_RAND
#define openssl_RAND_bytes(b,n) RAND_OpenSSL()->bytes((b), (n))
#define openssl_RAND_add(b,n,e) RAND_OpenSSL()->add((b), (n), (e))
#else
#define openssl_RAND_bytes(b,n) RAND_bytes((b),(n))
#define openssl_RAND_add(b,n,e) do {} while (0)
#endif

/**
 * Refill the PRNG: that is, fill the buffer with pseudorandom output of
 * the SHAKE XOF function, using as inputs:
 * <ul>
 *    <li> OpenSSL's RAND_bytes function
 *    <li> The previous first PRNG_CARRYFORWARD bytes of the buffer
 *         (so that once the PRNG has been seeded, it stays unpredictable).
 *    <li> The operating system's arc4random_buf function (if present)
 *    <li> The <b>n</b> bytes of input in <b>seed</b>, if they are
 *         provided.  (We use this to add entropy from the OS.)
 * </ul>
 *
 * The caller MUST hold the mutex.
 */
static void
shake_prng_refill(shake_prng_t *prng, const uint8_t *seed, size_t n)
{
  /* Structure for our fixed-length inputs. We leave any unused fields set
   * to 0, since that's easier than adding them conditionally. */
  struct {
    uint8_t from_ourself[PRNG_CARRYFORWARD];
    uint8_t from_openssl[PRNG_OPENSSL_BYTES];
#ifdef HAVE_ARC4RANDOM_BUF
    uint8_t from_libc[PRNG_LIBC_BYTES];
#endif
  } input;

  const char tweak[] = "shake prng update";

  memset(&input, 0, sizeof(input));

  ++prng->refill_count;

  memcpy(input.from_ourself, prng->sh.carryforward, PRNG_CARRYFORWARD);
  {
    int r = openssl_RAND_bytes(input.from_openssl, PRNG_OPENSSL_BYTES);
    tor_assert(r>0);
  }

#ifdef HAVE_ARC4RANDOM_BUF
  arc4random_buf(input.from_libc, sizeof(input.from_libc));
#endif

  {
    keccak_state shake;
    int r = keccak_xof_init(&shake, PRNG_SHAKE_BITS);
    tor_assert(r == 0);
    keccak_xof_absorb(&shake, (const uint8_t*)tweak, sizeof(tweak));
    keccak_xof_absorb(&shake, (const uint8_t*)&input, sizeof(input));
    if (seed && n) {
      keccak_xof_absorb(&shake, seed, n);
    }
    keccak_xof_squeeze(&shake, (void *)&prng->sh, sizeof(prng->sh));
    keccak_cleanse(&shake);
  }

  prng->remaining = sizeof(prng->sh.buf);
  prng->ptr = prng->sh.buf;
  memwipe(&input, 0, sizeof(input));
}

/**
 * Extract <b>n</b> pseudorandom bytes from the PRNG, and write them into
 * <b>out</b>.
 *
 * Caller MUST hold the mutex.
 */
static void
shake_prng_getbytes_raw(shake_prng_t *prng, uint8_t *out, size_t n)
{
#ifdef HAVE_PID
  /* Thou shalt not fork without calling crypto_shake_prng_postfork */
  tor_assert(getpid() == prng->pid);
#endif
  shake_prng_test_invariants(prng);

  /* While we still want any bytes... */
  while (n) {
    /* How many bytes should we extract this time through the loop? */
    size_t sz = n > prng->remaining ? prng->remaining : n;

    /* Extract the bytes and clear them from the buffer as we do
     * (for backtracking resistance) */
    memcpy(out, prng->ptr, sz);
    memset(prng->ptr, 0, sz);

    /* Advance the pointer */
    prng->ptr += sz;
    prng->remaining -= sz;

    /* Decrease the number of bytes wanted */
    n -= sz;

    /* Refill the buffer if we just emptied it. */
    if (prng->remaining == 0) {
      shake_prng_refill(prng, NULL, 0);
    }
  }
  shake_prng_test_invariants(prng);
}

/**
 * Fill a large buffer in <b>out</b> using the SHAKE XOF, using a small number
 * of bytes from the PRNG.
 *
 * This makes fewer calls to SHAKE, and holds the lock for much less longer,
 * than would be needed to call shake_prng_getbytes_raw().
 *
 * Callers MUST NOT hold the mutex.
 */
static void
shake_prng_getbytes_large(shake_prng_t *prng, uint8_t *out, size_t n)
{
  keccak_state shake;
  uint8_t buf[PRNG_CARRYFORWARD];
  const char tweak[] = "expand keccak prng";

  /* Grab the mutex, fill <b>buf</b>, and release the mutex immediately.*/
  tor_mutex_acquire(&prng_mutex);
  shake_prng_getbytes_raw(prng, buf, sizeof(buf));
  tor_mutex_release(&prng_mutex);

  /* Fill the output target, without holding the mutex. */
  int r = keccak_xof_init(&shake, PRNG_SHAKE_BITS);
  tor_assert(r == 0);
  keccak_xof_absorb(&shake, (const uint8_t*)tweak, sizeof(tweak));
  keccak_xof_absorb(&shake, buf, sizeof(buf));
  keccak_xof_squeeze(&shake, out, n);

  /* Clean up */
  keccak_cleanse(&shake);
  memwipe(buf, 0, sizeof(buf));
}

/**
 * Extract <b>n</b> bytes from the PRNG, using an appropriately fast method.
 *
 * Callers MUST NOT hold the mutex.
 */
static void
shake_prng_getbytes(shake_prng_t *prng, uint8_t *out, size_t n)
{
  if (n > 128) {
    shake_prng_getbytes_large(prng, out, n);
    return;
  }

  tor_mutex_acquire(&prng_mutex);
  shake_prng_getbytes_raw(prng, out, n);
  tor_mutex_release(&prng_mutex);
}

/** Write <b>n</b> bytes of strong random data to <b>to</b>. Supports mocking
 * for unit tests.
 *
 * This function is not allowed to fail; if it would fail to generate strong
 * entropy, it must terminate the process instead.
 */
MOCK_IMPL(void,
crypto_rand, (char *to, size_t n))
{
  crypto_rand_unmocked(to, n);
}

/** Write <b>n</b> bytes of strong random data to <b>to</b>.  Most callers
 * will want crypto_rand instead.
 *
 * This function is not allowed to fail; if it would fail to generate strong
 * entropy, it must terminate the process instead.
 */
void
crypto_rand_unmocked(char *to, size_t n)
{
  if (n == 0)
    return;

  tor_assert(to);
  shake_prng_getbytes(the_prng, (uint8_t*)to, n);
}

/**
 * Inform the PRNG that fork() has completed, and the PRNG state needs to
 * be updated.
 *
 * If the PRNG has been initialized, and fork() has been called, this function
 * MUST be called before using the PRNG again.  Most likely, Tor will
 * detect that you've messed up and crash.  But if you're unlucky, the PRNG
 * output will be (unsecurely!) repeated.
 *
 * Callers MUST NOT hold the mutex.
 */
void
crypto_shake_prng_postfork(void)
{
  tor_mutex_acquire(&prng_mutex);
  shake_prng_t *prng = the_prng;
  /* Prevent anything else touching the PRNG while this is happening. */
  the_prng = NULL;
  tor_mutex_release(&prng_mutex);

  /* Reseed the PRNG. */
  shake_prng_reseed(prng);

  tor_mutex_acquire(&prng_mutex);
  /* Put the PRNG back in place. */
  the_prng = prng;
  shake_prng_test_invariants(prng);
  tor_mutex_release(&prng_mutex);
}

/** Check whether the PRNG has gone for long enough (in time) or refilled
 * itself enough times that we would like to pull in more entropy from the OS.
 * If so, do so.
 */
void
crypto_shake_prng_check_reseed(int force)
{
  const time_t now = time(NULL);

  tor_mutex_acquire(&prng_mutex);
  int should_reseed = 0;
  if (! the_prng->reseeding) {
    should_reseed = force ||
      (the_prng->refill_count > PRNG_RESEED_AFTER) ||
      (the_prng->last_reseeded < now - PRNG_RESEED_AFTER_TIME);
  }
  if (should_reseed) {
    /* We set 'reseeding' here, and check it above, so that we don't launch two
     * simultaneous reseeds. */
    the_prng->reseeding = 1;
  }
  /* Now we're going to let go of the lock.  If we want to reseed, we'll
   * do so right afterwards.
   */
  tor_mutex_release(&prng_mutex);

  if (!should_reseed)
    return;

  shake_prng_reseed(the_prng);
}

/**
 * Clean up and release all resources allocated by the PRNG.
 */
void
crypto_teardown_shake_prng(void)
{
  tor_mutex_acquire(&prng_mutex);
  shake_prng_t *prng = the_prng;
  the_prng = NULL;
  shake_prng_test_invariants(prng);
  tor_mutex_release(&prng_mutex);

  free_prng_page(prng);
}

#ifdef CHECK_INVARIANTS
/**
 * Assert that the PRNG's state looks reasonable.
 * The caller must hold the mutex. */
static void
shake_prng_test_invariants(const shake_prng_t *prng)
{
  tor_assert(prng->remaining > 0);
  tor_assert(prng->remaining <= sizeof(prng->sh.buf));
  tor_assert(prng->ptr == prng->sh.buf +
    (sizeof(prng->sh.buf) - prng->remaining));
  tor_assert(tor_mem_is_zero((const void*)prng->sh.buf,
                             sizeof(prng->sh.buf) - prng->remaining));
#ifdef HAVE_PID
  tor_assert(prng->pid == getpid());
#endif
}
#endif

#ifdef REPLACE_OPENSSL_RAND
/**
 * Tor doesn't really need this, but we might as well have it: it's
 * a wrapper for adding bytes to the RNG.
 */
static void
shake_prng_addseed(shake_prng_t *prng, const uint8_t *inp, size_t n)
{
  tor_mutex_acquire(&prng_mutex);
  shake_prng_refill(prng, inp, n);
  shake_prng_test_invariants(prng);
  tor_mutex_release(&prng_mutex);
}

/**
 * Wrapper functions for our PRNG so that OpenSSL can use it.
 * @{
 */
static void
ossl_shake_seed(const void *buf, int num)
{
  shake_prng_addseed(the_prng, buf, num);
}

static int
ossl_shake_bytes(unsigned char *buf, int num)
{
  shake_prng_getbytes(the_prng, buf, num);
  return 1;
}

static void
ossl_shake_cleanup(void)
{
  crypto_teardown_shake_prng(); /* ???? */
}

static void
ossl_shake_add(const void *buf, int num, double entropy)
{
  if (entropy >= 0.5) {
    ossl_shake_seed(buf, num);

    /* And feed a little back to openssl. */
    uint8_t b[16];
    shake_prng_getbytes(the_prng, b, 16);
    openssl_RAND_add(b, 16, entropy > 16 ? 16.0 : entropy);
  } else {
    /* Openssl thinks it's being clever; it just told us what time it is
     * or something like that.  This isn't worth stopping for.
     */
  }
}

static int
ossl_shake_status(void)
{
  return 1;
}

static const struct rand_meth_st ossl_shake_method = {
  ossl_shake_seed,
  ossl_shake_bytes,
  ossl_shake_cleanup,
  ossl_shake_add,
  ossl_shake_bytes, /* Pseudorand? Why would we make one of those? */
  ossl_shake_status
};

/**
 * Replace OpenSSL's PRNG with ours.
 */
static void
usurp_openssl_rand_method(void)
{
  RAND_set_rand_method(&ossl_shake_method);
}
#endif

/* XXXX we should move our other (P)RAND functions into this file. */
