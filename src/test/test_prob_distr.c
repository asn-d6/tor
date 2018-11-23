/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_prob_distr.c
 * \brief Test probability distributions.
 * \detail
 *
 * For each probability distribution we do two kinds of tests:
 *
 * a) We do numerical deterministic testing of their cdf/icdf/sf/isf functions
 *    and the various relationships between them for each distribution. We also
 *    do deterministic tests on their sampling functions. Test vectors for
 *    these tests were computed from alternative implementations and were
 *    eyeballed to make sure they make sense (e.g. GNU mpfr was used with
 *    200-bit precision).
 *
 * b) We do stochastic hypothesis testing (G-test) to ensure that sampling from
 *    the given distributions is distributed properly. The stochastic tests are
 *    slow and their false positive rate is not well suited for CI, so they are
 *    currently disabled-by-default and put into 'tests-slow'.
 */

#define PROB_DISTR_PRIVATE

#include "orconfig.h"

#include "test/test.h"

#include "core/or/or.h"

#include "lib/math/prob_distr.h"
#include "lib/crypt_ops/crypto_rand.h"

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/** Return the integer part of double <b>d</b>. If <b>use_floor</b> is true,
 *  then use the floor() function otherwise use ceil(). */
static size_t
get_size_t_from_double(double d, bool use_floor)
{
  double integral_d = use_floor ? floor(d) : ceil(d);
  return (size_t) integral_d;
}

/*
 * Geometric(p) distribution, supported on {1, 2, 3, ...}.
 *
 * Compute the probability mass function Geom(n; p) of the number of
 * trials before the first success when success has probability p.
 */
static double
logpmf_geometric(unsigned n, double p)
{

  if (p >= 1) {                 /* XXX -Wfloat-equal */
    if (n == 1)
      return 0;
    else
      return -HUGE_VAL;
  }
  return (n - 1)*log1p(-p) + log(p);
}

/**
 * Compute the logistic function, translated in output by 1/2:
 * logistichalf(x) = logistic(x) - 1/2.  Well-conditioned on the entire
 * real plane, with maximum condition number 1 at 0.
 *
 * This implementation gives relative error bounded by 5 eps.
 */
static double
logistichalf(double x)
{
  /*
   * Rewrite this with the identity
   *
   *  1/(1 + e^{-x}) - 1/2
   *  = (1 - 1/2 - e^{-x}/2)/(1 + e^{-x})
   *  = (1/2 - e^{-x}/2)/(1 + e^{-x})
   *  = (1 - e^{-x})/[2 (1 + e^{-x})]
   *  = -(e^{-x} - 1)/[2 (1 + e^{-x})],
   *
   * which we can evaluate by -expm1(-x)/[2 (1 + exp(-x))].
   *
   * Suppose exp has error d0, + has error d1, expm1 has error
   * d2, and / has error d3, so we evaluate
   *
   *  -(1 + d2) (1 + d3) (e^{-x} - 1)
   *    / [2 (1 + d1) (1 + (1 + d0) e^{-x})].
   *
   * In the denominator,
   *
   *  1 + (1 + d0) e^{-x}
   *  = 1 + e^{-x} + d0 e^{-x}
   *  = (1 + e^{-x}) (1 + d0 e^{-x}/(1 + e^{-x})),
   *
   * so the relative error of the numerator is
   *
   *  d' = d2 + d3 + d2 d3,
   * and of the denominator,
   *  d'' = d1 + d0 e^{-x}/(1 + e^{-x}) + d0 d1 e^{-x}/(1 + e^{-x})
   *      = d1 + d0 L(-x) + d0 d1 L(-x),
   *
   * where L(-x) is logistic(-x).  By Lemma 1 the relative error
   * of the quotient is bounded by
   *
   *  2|d2 + d3 + d2 d3 - d1 - d0 L(x) + d0 d1 L(x)|,
   *
   * Since 0 < L(x) < 1, this is bounded by
   *
   *  2|d2| + 2|d3| + 2|d2 d3| + 2|d1| + 2|d0| + 2|d0 d1|
   *  <= 4 eps + 2 eps^2.
   */
  if (x < log(DBL_EPSILON/8)) {
    /*
     * Avoid overflow in e^{-x}.  When x < log(eps/4), we
     * we further have x < logit(eps/4), so that
     * logistic(x) < eps/4.  Hence the relative error of
     * logistic(x) - 1/2 from -1/2 is bounded by eps/2, and
     * so the relative error of -1/2 from logistic(x) - 1/2
     * is bounded by eps.
     */
    return -0.5;
  } else {
    return -expm1(-x)/(2*(1 + exp(-x)));
  }
}

/**
 * Compute the log of the sum of the exps.  Caller should arrange the
 * array in descending order to minimize error because I don't want to
 * deal with using temporary space and the one caller in this file
 * arranges that anyway.
 *
 * Warning: This implementation does not handle infinite or NaN inputs
 * sensibly, because I don't need that here at the moment.  (NaN, or
 * -inf and +inf together, should yield NaN; +inf and finite should
 * yield +inf; otherwise all -inf should be ignored because exp(-inf) =
 * 0.)
 */
static double
logsumexp(double *A, size_t n)
{
  double maximum, sum;
  size_t i;

  if (n == 0)
    return log(0);

  maximum = A[0];
  for (i = 1; i < n; i++) {
    if (A[i] > maximum)
      maximum = A[i];
  }

  sum = 0;
  for (i = n; i --> 0;)
    sum += exp(A[i] - maximum);

  return log(sum) + maximum;
}

/**
 * Compute log(1 - e^x).  Defined only for negative x so that e^x < 1.
 * This is the complement of a probability in log space.
 */
static double
log1mexp(double x)
{

  /*
   * We want to compute log on [0, 1/2) but log1p on [1/2, +inf),
   * so partition x at -log(2) = log(1/2).
   */
  if (-log(2) < x)
    return log(-expm1(x));
  else
    return log1p(-exp(x));
}

/*
 * Tests of numerical errors in computing logit, logistic, and the
 * various cdfs, sfs, icdfs, and isfs.
 */

#define arraycount(A) (sizeof(A)/sizeof(A[0]))

/** Return relative error between <b>actual</b> and <b>expected</b>. */
static double
relerr(double expected, double actual)
{
  if (fabs(expected) <= 0 || isinf(expected)) { /* XXX -Wfloat-equal */
    if (actual <= expected && actual >= expected)
      return 0;
    else
      return 1;
  } else {
    return fabs((expected - actual)/expected);
  }
}

/** Check that relative error of <b>expected</b> and <b>actual</b> is within
 *  <b>relerr_bound</b>.  Caller must arrange to have i and relerr_bound in
 *  scope.  */
#define CHECK_RELERR(expected, actual) do {                                   \
  double check_expected = (expected);                                         \
  double check_actual = (actual);                                             \
  double check_relerr = relerr(expected, actual);                             \
  if (!(relerr(check_expected, check_actual) <= relerr_bound)) {              \
    printf("%s:%d: case %zu: relerr(%s=%.17e, %s=%.17e)"                      \
        " = %.17e > %.17e\n",                                                 \
        __func__, __LINE__, i,                                                \
        #expected, check_expected,                                            \
        #actual, check_actual,                                                \
        check_relerr, relerr_bound);                                          \
    ok = false;                                                               \
  }                                                                           \
} while (0)

/* Check that a <= b.
 * Caller must arrange to have i in scope.  */
#define CHECK_LE(a, b) do {                                                   \
  double check_a = (a);                                                       \
  double check_b = (b);                                                       \
  if (check_a > check_b) {                                                    \
    printf("%s:%d: case %zu: %s=%.17e > %s=%.17e\n",                          \
        __func__, __LINE__, i,                                                \
        #a, check_a, #b, check_b);                                            \
    ok = false;                                                               \
  }                                                                           \
} while (0)

/**
 * Test the logit and logistic functions.  Confirm that they agree with
 * the cdf, sf, icdf, and isf of the standard Logistic distribution.
 * Confirm that the sampler for the standard logistic distribution maps
 * [0, 1] into the right subinterval for the inverse transform, for
 * this implementation.
 */
static void
test_logit_logistic(void *arg)
{
  (void) arg;

  static const struct {
    double x;                   /* x = logit(p) */
    double p;                   /* p = logistic(x) */
    double phalf;               /* p - 1/2 = logistic(x) - 1/2 */
  } cases[] = {
    { -HUGE_VAL, 0, -0.5 },
    { -1000, 0, -0.5 },
    { -710, 4.47628622567513e-309, -0.5 },
    { -708, 3.307553003638408e-308, -0.5 },
    { -2, .11920292202211755, -.3807970779778824 },
    { -1.0000001, .2689414017088022, -.23105859829119776 },
    { -1, .2689414213699951, -.23105857863000487 },
    { -0.9999999, .26894144103118883, -.2310585589688111 },
    { -4.000000000537333e-5, .49999, -1.0000000000010001e-5 },
    { -4.000000000533334e-5, .49999, -.00001 },
    { -4.000000108916878e-9, .499999999, -1.0000000272292198e-9 },
    { -4e-9, .499999999, -1e-9 },
    { -4e-16, .5, -1e-16 },
    { -4e-300, .5, -1e-300 },
    { 0, .5, 0 },
    { 4e-300, .5, 1e-300 },
    { 4e-16, .5, 1e-16 },
    { 3.999999886872274e-9, .500000001, 9.999999717180685e-10 },
    { 4e-9, .500000001, 1e-9 },
    { 4.0000000005333336e-5, .50001, .00001 },
    { 8.000042667076272e-3, .502, .002 },
    { 0.9999999, .7310585589688111, .2310585589688111 },
    { 1, .7310585786300049, .23105857863000487 },
    { 1.0000001, .7310585982911977, .23105859829119774 },
    { 2, .8807970779778823, .3807970779778824 },
    { 708, 1, .5 },
    { 710, 1, .5 },
    { 1000, 1, .5 },
    { HUGE_VAL, 1, .5 },
  };
  double relerr_bound = 3e-15; /* >10eps */
  size_t i;
  bool ok = true;

  for (i = 0; i < arraycount(cases); i++) {
    double x = cases[i].x;
    double p = cases[i].p;
    double phalf = cases[i].phalf;

    /*
     * cdf is logistic, icdf is logit, and symmetry for
     * sf/isf.
     */
    CHECK_RELERR(logistic(x), cdf_logistic(x, 0, 1));
    CHECK_RELERR(logistic(-x), sf_logistic(x, 0, 1));
    CHECK_RELERR(logit(p), icdf_logistic(p, 0, 1));
    CHECK_RELERR(-logit(p), isf_logistic(p, 0, 1));

    CHECK_RELERR(cdf_logistic(x, 0, 1), cdf_logistic(x*2, 0, 2));
    CHECK_RELERR(sf_logistic(x, 0, 1), sf_logistic(x*2, 0, 2));
    CHECK_RELERR(icdf_logistic(p, 0, 1), icdf_logistic(p, 0, 2)/2);
    CHECK_RELERR(isf_logistic(p, 0, 1), isf_logistic(p, 0, 2)/2);

    CHECK_RELERR(cdf_logistic(x, 0, 1), cdf_logistic(x/2, 0, .5));
    CHECK_RELERR(sf_logistic(x, 0, 1), sf_logistic(x/2, 0, .5));
    CHECK_RELERR(icdf_logistic(p, 0, 1), icdf_logistic(p, 0,.5)*2);
    CHECK_RELERR(isf_logistic(p, 0, 1), isf_logistic(p, 0, .5)*2);

    CHECK_RELERR(cdf_logistic(x, 0, 1), cdf_logistic(x*2 + 1, 1, 2));
    CHECK_RELERR(sf_logistic(x, 0, 1), sf_logistic(x*2 + 1, 1, 2));

    /*
     * For p near 0 and p near 1/2, the arithmetic of
     * translating by 1 loses precision.
     */
    if (fabs(p) > DBL_EPSILON && fabs(p) < 0.4) {
      CHECK_RELERR(icdf_logistic(p, 0, 1),
          (icdf_logistic(p, 1, 2) - 1)/2);
      CHECK_RELERR(isf_logistic(p, 0, 1),
          (isf_logistic(p, 1, 2) - 1)/2);
    }

    CHECK_RELERR(p, logistic(x));
    CHECK_RELERR(phalf, logistichalf(x));

    /*
     * On the interior floating-point numbers, either logit or
     * logithalf had better give the correct answer.
     *
     * For probabilities near 0, we can get much finer resolution with
     * logit, and for probabilities near 1/2, we can get much finer
     * resolution with logithalf by representing them using p - 1/2.
     *
     * E.g., we can write -.00001 for phalf, and .49999 for p, but the
     * difference 1/2 - .00001 gives 1.0000000000010001e-5 in binary64
     * arithmetic.  So test logit(.49999) which should give the same
     * answer as logithalf(-1.0000000000010001e-5), namely
     * -4.000000000537333e-5, and also test logithalf(-.00001) which
     * gives -4.000000000533334e-5 instead -- but don't expect
     * logit(.49999) to give -4.000000000533334e-5 even though it looks
     * like 1/2 - .00001.
     *
     * A naive implementation of logit will just use log(p/(1 - p)) and
     * give the answer -4.000000000551673e-05 for .49999, which is
     * wrong in a lot of digits, which happens because log is
     * ill-conditioned near 1 and thus amplifies whatever relative
     * error we made in computing p/(1 - p).
     */
    if ((0 < p && p < 1) || isinf(x)) {
      if (phalf >= p - 0.5 && phalf <= p - 0.5) /* XXX -Wfloat-equal */
        CHECK_RELERR(x, logit(p));
      if (p >= 0.5 + phalf && p <= 0.5 + phalf) /* XXX -Wfloat-equal */
        CHECK_RELERR(x, logithalf(phalf));
    }

    CHECK_RELERR(-phalf, logistichalf(-x));
    if (fabs(phalf) < 0.5 || isinf(x))
      CHECK_RELERR(-x, logithalf(-phalf));
    if (p < 1 || isinf(x)) {
      CHECK_RELERR(1 - p, logistic(-x));
      if (p > .75 || isinf(x))
        CHECK_RELERR(-x, logit(1 - p));
    } else {
      CHECK_LE(logistic(-x), 1e-300);
    }
  }

  for (i = 0; i <= 100; i++) {
    double p0 = (double)i/100;

    CHECK_RELERR(logit(p0/(1 + M_E)), sample_logistic(0, 0, p0));
    CHECK_RELERR(-logit(p0/(1 + M_E)), sample_logistic(1, 0, p0));
    CHECK_RELERR(logithalf(p0*(0.5 - 1/(1 + M_E))),
        sample_logistic(0, 1, p0));
    CHECK_RELERR(-logithalf(p0*(0.5 - 1/(1 + M_E))),
        sample_logistic(1, 1, p0));
  }

  if (!ok)
    printf("fail logit/logistic / logistic cdf/sf\n");

  tt_assert(ok);

 done:
  ;
}

/**
 * Test the cdf, sf, icdf, and isf of the LogLogistic distribution.
 */
static void
test_log_logistic(void *arg)
{
  (void) arg;

  static const struct {
    double x;
    double p;
    double np;
  } cases[] = {
    { 0, 0, 1 },
    { 1e-300, 1e-300, 1 },
    { 1e-17, 1e-17, 1 },
    { 1e-15, 1e-15, .999999999999999 },
    { .1, .09090909090909091, .90909090909090909 },
    { .25, .2, .8 },
    { .5, .33333333333333333, .66666666666666667 },
    { .75, .42857142857142855, .5714285714285714 },
    { .9999, .49997499874993756, .5000250012500626 },
    { .99999999, .49999999749999996, .5000000025 },
    { .999999999999999, .49999999999999994, .5000000000000002 },
    { 1, .5, .5 },
  };
  double relerr_bound = 3e-15;
  size_t i;
  bool ok = true;

  for (i = 0; i < arraycount(cases); i++) {
    double x = cases[i].x;
    double p = cases[i].p;
    double np = cases[i].np;

    CHECK_RELERR(p, cdf_log_logistic(x, 1, 1));
    CHECK_RELERR(p, cdf_log_logistic(x/2, .5, 1));
    CHECK_RELERR(p, cdf_log_logistic(x*2, 2, 1));
    CHECK_RELERR(p, cdf_log_logistic(sqrt(x), 1, 2));
    CHECK_RELERR(p, cdf_log_logistic(sqrt(x)/2, .5, 2));
    CHECK_RELERR(p, cdf_log_logistic(sqrt(x)*2, 2, 2));
    if (2*sqrt(DBL_MIN) < x) {
      CHECK_RELERR(p, cdf_log_logistic(x*x, 1, .5));
      CHECK_RELERR(p, cdf_log_logistic(x*x/2, .5, .5));
      CHECK_RELERR(p, cdf_log_logistic(x*x*2, 2, .5));
    }

    CHECK_RELERR(np, sf_log_logistic(x, 1, 1));
    CHECK_RELERR(np, sf_log_logistic(x/2, .5, 1));
    CHECK_RELERR(np, sf_log_logistic(x*2, 2, 1));
    CHECK_RELERR(np, sf_log_logistic(sqrt(x), 1, 2));
    CHECK_RELERR(np, sf_log_logistic(sqrt(x)/2, .5, 2));
    CHECK_RELERR(np, sf_log_logistic(sqrt(x)*2, 2, 2));
    if (2*sqrt(DBL_MIN) < x) {
      CHECK_RELERR(np, sf_log_logistic(x*x, 1, .5));
      CHECK_RELERR(np, sf_log_logistic(x*x/2, .5, .5));
      CHECK_RELERR(np, sf_log_logistic(x*x*2, 2, .5));
    }

    CHECK_RELERR(np, cdf_log_logistic(1/x, 1, 1));
    CHECK_RELERR(np, cdf_log_logistic(1/(2*x), .5, 1));
    CHECK_RELERR(np, cdf_log_logistic(2/x, 2, 1));
    CHECK_RELERR(np, cdf_log_logistic(1/sqrt(x), 1, 2));
    CHECK_RELERR(np, cdf_log_logistic(1/(2*sqrt(x)), .5, 2));
    CHECK_RELERR(np, cdf_log_logistic(2/sqrt(x), 2, 2));
    if (2*sqrt(DBL_MIN) < x && x < 1/(2*sqrt(DBL_MIN))) {
      CHECK_RELERR(np, cdf_log_logistic(1/(x*x), 1, .5));
      CHECK_RELERR(np, cdf_log_logistic(1/(2*x*x), .5, .5));
      CHECK_RELERR(np, cdf_log_logistic(2/(x*x), 2, .5));
    }

    CHECK_RELERR(p, sf_log_logistic(1/x, 1, 1));
    CHECK_RELERR(p, sf_log_logistic(1/(2*x), .5, 1));
    CHECK_RELERR(p, sf_log_logistic(2/x, 2, 1));
    CHECK_RELERR(p, sf_log_logistic(1/sqrt(x), 1, 2));
    CHECK_RELERR(p, sf_log_logistic(1/(2*sqrt(x)), .5, 2));
    CHECK_RELERR(p, sf_log_logistic(2/sqrt(x), 2, 2));
    if (2*sqrt(DBL_MIN) < x && x < 1/(2*sqrt(DBL_MIN))) {
      CHECK_RELERR(p, sf_log_logistic(1/(x*x), 1, .5));
      CHECK_RELERR(p, sf_log_logistic(1/(2*x*x), .5, .5));
      CHECK_RELERR(p, sf_log_logistic(2/(x*x), 2, .5));
    }

    CHECK_RELERR(x, icdf_log_logistic(p, 1, 1));
    CHECK_RELERR(x/2, icdf_log_logistic(p, .5, 1));
    CHECK_RELERR(x*2, icdf_log_logistic(p, 2, 1));
    CHECK_RELERR(x, icdf_log_logistic(p, 1, 1));
    CHECK_RELERR(sqrt(x)/2, icdf_log_logistic(p, .5, 2));
    CHECK_RELERR(sqrt(x)*2, icdf_log_logistic(p, 2, 2));
    CHECK_RELERR(sqrt(x), icdf_log_logistic(p, 1, 2));
    CHECK_RELERR(x*x/2, icdf_log_logistic(p, .5, .5));
    CHECK_RELERR(x*x*2, icdf_log_logistic(p, 2, .5));

    if (np < .9) {
      CHECK_RELERR(x, isf_log_logistic(np, 1, 1));
      CHECK_RELERR(x/2, isf_log_logistic(np, .5, 1));
      CHECK_RELERR(x*2, isf_log_logistic(np, 2, 1));
      CHECK_RELERR(sqrt(x), isf_log_logistic(np, 1, 2));
      CHECK_RELERR(sqrt(x)/2, isf_log_logistic(np, .5, 2));
      CHECK_RELERR(sqrt(x)*2, isf_log_logistic(np, 2, 2));
      CHECK_RELERR(x*x, isf_log_logistic(np, 1, .5));
      CHECK_RELERR(x*x/2, isf_log_logistic(np, .5, .5));
      CHECK_RELERR(x*x*2, isf_log_logistic(np, 2, .5));

      CHECK_RELERR(1/x, icdf_log_logistic(np, 1, 1));
      CHECK_RELERR(1/(2*x), icdf_log_logistic(np, .5, 1));
      CHECK_RELERR(2/x, icdf_log_logistic(np, 2, 1));
      CHECK_RELERR(1/sqrt(x), icdf_log_logistic(np, 1, 2));
      CHECK_RELERR(1/(2*sqrt(x)),
          icdf_log_logistic(np, .5, 2));
      CHECK_RELERR(2/sqrt(x), icdf_log_logistic(np, 2, 2));
      CHECK_RELERR(1/(x*x), icdf_log_logistic(np, 1, .5));
      CHECK_RELERR(1/(2*x*x), icdf_log_logistic(np, .5, .5));
      CHECK_RELERR(2/(x*x), icdf_log_logistic(np, 2, .5));
    }

    CHECK_RELERR(1/x, isf_log_logistic(p, 1, 1));
    CHECK_RELERR(1/(2*x), isf_log_logistic(p, .5, 1));
    CHECK_RELERR(2/x, isf_log_logistic(p, 2, 1));
    CHECK_RELERR(1/sqrt(x), isf_log_logistic(p, 1, 2));
    CHECK_RELERR(1/(2*sqrt(x)), isf_log_logistic(p, .5, 2));
    CHECK_RELERR(2/sqrt(x), isf_log_logistic(p, 2, 2));
    CHECK_RELERR(1/(x*x), isf_log_logistic(p, 1, .5));
    CHECK_RELERR(1/(2*x*x), isf_log_logistic(p, .5, .5));
    CHECK_RELERR(2/(x*x), isf_log_logistic(p, 2, .5));
  }

  for (i = 0; i <= 100; i++) {
    double p0 = (double)i/100;

    CHECK_RELERR(0.5*p0/(1 - 0.5*p0), sample_log_logistic(0, p0));
    CHECK_RELERR((1 - 0.5*p0)/(0.5*p0),
        sample_log_logistic(1, p0));
  }

  if (!ok)
    printf("fail log logistic cdf/sf\n");

  tt_assert(ok);

 done:
  ;
}

/**
 * Test the cdf, sf, icdf, isf of the Weibull distribution.
 */
static void
test_weibull(void *arg)
{
  (void) arg;

  static const struct {
    double x;
    double p;
    double np;
  } cases[] = {
    { 0, 0, 1 },
    { 1e-300, 1e-300, 1 },
    { 1e-17, 1e-17, 1 },
    { .1, .09516258196404043, .9048374180359595 },
    { .5, .3934693402873666, .6065306597126334 },
    { .6931471805599453, .5, .5 },
    { 1, .6321205588285577, .36787944117144233 },
    { 10, .9999546000702375, 4.5399929762484854e-5 },
    { 36, .9999999999999998, 2.319522830243569e-16 },
    { 37, .9999999999999999, 8.533047625744066e-17 },
    { 38, 1, 3.1391327920480296e-17 },
    { 100, 1, 3.720075976020836e-44 },
    { 708, 1, 3.307553003638408e-308 },
    { 710, 1, 4.47628622567513e-309 },
    { 1000, 1, 0 },
    { HUGE_VAL, 1, 0 },
  };
  double relerr_bound = 3e-15;
  size_t i;
  bool ok = true;

  for (i = 0; i < arraycount(cases); i++) {
    double x = cases[i].x;
    double p = cases[i].p;
    double np = cases[i].np;

    CHECK_RELERR(p, cdf_weibull(x, 1, 1));
    CHECK_RELERR(p, cdf_weibull(x/2, .5, 1));
    CHECK_RELERR(p, cdf_weibull(x*2, 2, 1));
    /* For 0 < x < sqrt(DBL_MIN), x^2 loses lots of bits.  */
    if (x <= 0 ||               /* XXX -Wfloat-equal */
        sqrt(DBL_MIN) <= x) {
      CHECK_RELERR(p, cdf_weibull(x*x, 1, .5));
      CHECK_RELERR(p, cdf_weibull(x*x/2, .5, .5));
      CHECK_RELERR(p, cdf_weibull(x*x*2, 2, .5));
    }
    CHECK_RELERR(p, cdf_weibull(sqrt(x), 1, 2));
    CHECK_RELERR(p, cdf_weibull(sqrt(x)/2, .5, 2));
    CHECK_RELERR(p, cdf_weibull(sqrt(x)*2, 2, 2));
    CHECK_RELERR(np, sf_weibull(x, 1, 1));
    CHECK_RELERR(np, sf_weibull(x/2, .5, 1));
    CHECK_RELERR(np, sf_weibull(x*2, 2, 1));
    CHECK_RELERR(np, sf_weibull(x*x, 1, .5));
    CHECK_RELERR(np, sf_weibull(x*x/2, .5, .5));
    CHECK_RELERR(np, sf_weibull(x*x*2, 2, .5));
    if (x >= 10) {
      /*
       * exp amplifies the error of sqrt(x)^2
       * proportionally to exp(x); for large inputs
       * this is significant.
       */
      double t = -expm1(-x*(2*DBL_EPSILON + DBL_EPSILON));
      relerr_bound = t + DBL_EPSILON + t*DBL_EPSILON;
      if (relerr_bound < 3e-15)
        /*
         * The tests are written only to 16
         * decimal places anyway even if your
         * `double' is, say, i387 binary80, for
         * whatever reason.
         */
        relerr_bound = 3e-15;
      CHECK_RELERR(np, sf_weibull(sqrt(x), 1, 2));
      CHECK_RELERR(np, sf_weibull(sqrt(x)/2, .5, 2));
      CHECK_RELERR(np, sf_weibull(sqrt(x)*2, 2, 2));
    }

    if (p <= 0.75) {
      /*
       * For p near 1, not enough precision near 1 to
       * recover x.
       */
      CHECK_RELERR(x, icdf_weibull(p, 1, 1));
      CHECK_RELERR(x/2, icdf_weibull(p, .5, 1));
      CHECK_RELERR(x*2, icdf_weibull(p, 2, 1));
    }
    if (p >= 0.25 && !isinf(x) && np > 0) {
      /*
       * For p near 0, not enough precision in np
       * near 1 to recover x.  For 0, isf gives inf,
       * even if p is precise enough for the icdf to
       * work.
       */
      CHECK_RELERR(x, isf_weibull(np, 1, 1));
      CHECK_RELERR(x/2, isf_weibull(np, .5, 1));
      CHECK_RELERR(x*2, isf_weibull(np, 2, 1));
    }
  }

  for (i = 0; i <= 100; i++) {
    double p0 = (double)i/100;

    CHECK_RELERR(3*sqrt(-log(p0/2)), sample_weibull(0, p0, 3, 2));
    CHECK_RELERR(3*sqrt(-log1p(-p0/2)),
        sample_weibull(1, p0, 3, 2));
  }

  if (!ok)
    printf("fail Weibull cdf/sf\n");

  tt_assert(ok);

 done:
  ;
}

/**
 * Test the cdf, sf, icdf, and isf of the generalized Pareto
 * distribution.
 */
static void
test_genpareto(void *arg)
{
  (void) arg;

  struct {
    double xi, x, p, np;
  } cases[] = {
    { 0, 0, 0, 1 },
    { 1e-300, .004, 3.992010656008528e-3, .9960079893439915 },
    { 1e-300, .1, .09516258196404043, .9048374180359595 },
    { 1e-300, 1, .6321205588285577, .36787944117144233 },
    { 1e-300, 10, .9999546000702375, 4.5399929762484854e-5 },
    { 1e-200, 1e-16, 9.999999999999999e-17, .9999999999999999 },
    { 1e-16, 1e-200, 9.999999999999998e-201, 1 },
    { 1e-16, 1e-16, 1e-16, 1 },
    { 1e-16, .004, 3.992010656008528e-3, .9960079893439915 },
    { 1e-16, .1, .09516258196404043, .9048374180359595 },
    { 1e-16, 1, .6321205588285577, .36787944117144233 },
    { 1e-16, 10, .9999546000702375, 4.539992976248509e-5 },
    { 1e-10, 1e-6, 9.999995000001667e-7, .9999990000005 },
    { 1e-8, 1e-8, 9.999999950000001e-9, .9999999900000001 },
    { 1, 1e-300, 1e-300, 1 },
    { 1, 1e-16, 1e-16, .9999999999999999 },
    { 1, .1, .09090909090909091, .9090909090909091 },
    { 1, 1, .5, .5 },
    { 1, 10, .9090909090909091, .0909090909090909 },
    { 1, 100, .9900990099009901, .0099009900990099 },
    { 1, 1000, .999000999000999, 9.990009990009992e-4 },
    { 10, 1e-300, 1e-300, 1 },
    { 10, 1e-16, 9.999999999999995e-17, .9999999999999999 },
    { 10, .1, .06696700846319258, .9330329915368074 },
    { 10, 1, .21320655780322778, .7867934421967723 },
    { 10, 10, .3696701667040189, .6303298332959811 },
    { 10, 100, .49886285755007337, .5011371424499267 },
    { 10, 1000, .6018968102992647, .3981031897007353 },
  };
  double xi_array[] = { -1.5, -1, -1e-30, 0, 1e-30, 1, 1.5 };
  size_t i, j;
  double relerr_bound = 3e-15;
  bool ok = true;

  for (i = 0; i < arraycount(cases); i++) {
    double xi = cases[i].xi;
    double x = cases[i].x;
    double p = cases[i].p;
    double np = cases[i].np;

    CHECK_RELERR(p, cdf_genpareto(x, 0, 1, xi));
    CHECK_RELERR(p, cdf_genpareto(x*2, 0, 2, xi));
    CHECK_RELERR(p, cdf_genpareto(x/2, 0, .5, xi));
    CHECK_RELERR(np, sf_genpareto(x, 0, 1, xi));
    CHECK_RELERR(np, sf_genpareto(x*2, 0, 2, xi));
    CHECK_RELERR(np, sf_genpareto(x/2, 0, .5, xi));

    if (p < .5) {
      CHECK_RELERR(x, icdf_genpareto(p, 0, 1, xi));
      CHECK_RELERR(x*2, icdf_genpareto(p, 0, 2, xi));
      CHECK_RELERR(x/2, icdf_genpareto(p, 0, .5, xi));
    }
    if (np < .5) {
      CHECK_RELERR(x, isf_genpareto(np, 0, 1, xi));
      CHECK_RELERR(x*2, isf_genpareto(np, 0, 2, xi));
      CHECK_RELERR(x/2, isf_genpareto(np, 0, .5, xi));
    }
  }

  for (i = 0; i < arraycount(xi_array); i++) {
    for (j = 0; j <= 100; j++) {
      double p0 = (j == 0 ? 2*DBL_MIN : (double)j/100);

      if (fabs(xi_array[i]) <= 0) { /* XXX -Wfloat-equal */
        /*
         * When xi == 0, the generalized Pareto
         * distribution reduces to an
         * exponential distribution.
         */
        CHECK_RELERR(-log(p0/2),
            sample_genpareto(0, p0, 0));
        CHECK_RELERR(-log1p(-p0/2),
            sample_genpareto(1, p0, 0));
      } else {
        CHECK_RELERR(expm1(-xi_array[i]*log(p0/2))/xi_array[i],
            sample_genpareto(0, p0, xi_array[i]));
        CHECK_RELERR((j == 0 ? DBL_MIN :
                expm1(-xi_array[i]*log1p(-p0/2))/xi_array[i]),
            sample_genpareto(1, p0, xi_array[i]));
      }

      CHECK_RELERR(isf_genpareto(p0/2, 0, 1, xi_array[i]),
          sample_genpareto(0, p0, xi_array[i]));
      CHECK_RELERR(icdf_genpareto(p0/2, 0, 1, xi_array[i]),
          sample_genpareto(1, p0, xi_array[i]));
    }
  }

  tt_assert(ok);

 done:
  ;
}

/**
 * Test the deterministic sampler for uniform distribution on [a, b].
 *
 * This currently only tests whether the outcome lies within [a, b].
 */
static void
test_uniform_interval(void *arg)
{
  (void) arg;
  struct {
    double t, a, b;
  } cases[] = {
    { 0, 0, 0 },
    { 0, 0, 1 },
    { 0, 1.0000000000000007, 3.999999999999995 },
    { 0, 4000, 4000 },
    { 0.42475836677491291, 4000, 4000 },
    { 0, -DBL_MAX, DBL_MAX },
    { 0.25, -DBL_MAX, DBL_MAX },
    { 0.5, -DBL_MAX, DBL_MAX },
  };
  size_t i = 0;
  bool ok = true;

  for (i = 0; i < arraycount(cases); i++) {
    double t = cases[i].t;
    double a = cases[i].a;
    double b = cases[i].b;

    CHECK_LE(a, sample_uniform_interval(t, a, b));
    CHECK_LE(sample_uniform_interval(t, a, b), b);

    CHECK_LE(a, sample_uniform_interval(1 - t, a, b));
    CHECK_LE(sample_uniform_interval(1 - t, a, b), b);

    CHECK_LE(sample_uniform_interval(t, -b, -a), -a);
    CHECK_LE(-b, sample_uniform_interval(t, -b, -a));

    CHECK_LE(sample_uniform_interval(1 - t, -b, -a), -a);
    CHECK_LE(-b, sample_uniform_interval(1 - t, -b, -a));
  }

  tt_assert(ok);

 done:
  ;
}

/*
 * Psi test, sometimes also called G-test.  The psi test statistic,
 * suitably scaled, has chi^2 distribution, but the psi test tends to
 * have better statistical power in practice to detect deviations than
 * the chi^2 test does.  (The chi^2 test statistic is the first term of
 * the Taylor expansion of the psi test statistic.)  The psi test is
 * generic, for any CDF; particular distributions might have higher-
 * power tests to distinguish them from predictable deviations or bugs.
 *
 * We choose the psi critical value so that a single psi test has
 * probability below alpha = 1% of spuriously failing even if all the
 * code is correct.  But the false positive rate for a suite of n tests
 * is higher: 1 - Binom(0; n, alpha) = 1 - (1 - alpha)^n.  For n = 10,
 * this is about 10%, and for n = 100 it is well over 50%.
 *
 * We can drive it down by running each test twice, and accepting it if
 * it passes at least once; in that case, it is as if we used Binom(2;
 * 2, alpha) = alpha^2 as the false positive rate for each test, and
 * for n = 10 tests, it would be 0.1%, and for n = 100 tests, still
 * only 1%.
 *
 * The critical value for a chi^2 distribution with 100 degrees of
 * freedom and false positive rate alpha = 1% was taken from:
 *
 *  NIST/SEMATECH e-Handbook of Statistical Methods, Section
 *  1.3.6.7.4 `Critical Values of the Chi-Square Distribution',
 *  <http://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm>,
 *  retrieved 2018-10-28.
 */

static const size_t NSAMPLES = 100000;
static const unsigned NTRIALS = 2;
static const unsigned NPASSES_MIN = 1;

#define PSI_DF 100                          /* degrees of freedom */
static const double PSI_CRITICAL = 135.807; /* critical value, alpha = .01 */

/**
 * Perform a psi test on an array of sample counts, C, adding up to N
 * samples, and an array of log expected probabilities, logP,
 * representing the null hypothesis for the distribution of samples
 * counted.  Return false if the psi test rejects the null hypothesis,
 * true if otherwise.
 */
static bool
psi_test(const size_t C[PSI_DF], const double logP[PSI_DF], size_t N)
{
  double psi = 0;
  double c = 0;                 /* Kahan compensation */
  double t, u;
  size_t i;

  for (i = 0; i < PSI_DF; i++) {
    /*
     * c*log(c/(n*p)) = (1/n) * f*log(f/p) where f = c/n is
     * the frequency, and f*log(f/p) ---> 0 as f ---> 0, so
     * this is a reasonable choice.  Further, any mass that
     * _fails_ to turn up in this bin will inflate another
     * bin instead, so we don't really lose anything by
     * ignoring empty bins even if they have high
     * probability.
     */
    if (C[i] == 0)
      continue;
    t = C[i]*(log((double)C[i]/N) - logP[i]) - c;
    u = psi + t;
    c = (u - psi) - t;
    psi = u;
  }
  psi *= 2;

  return psi <= PSI_CRITICAL;
}

static bool
test_stochastic_geometric_impl(double p)
{
  double logP[PSI_DF] = {0};
  unsigned ntry = NTRIALS, npass = 0;
  unsigned i;
  size_t j;

  /* Compute logP[i] = Geom(i + 1; p).  */
  for (i = 0; i < PSI_DF - 1; i++)
    logP[i] = logpmf_geometric(i + 1, p);

  /* Compute logP[n-1] = log (1 - (P[0] + P[1] + ... + P[n-2])).  */
  logP[PSI_DF - 1] = log1mexp(logsumexp(logP, PSI_DF - 1));

  while (ntry --> 0) {
    size_t C[PSI_DF] = {0};

    for (j = 0; j < NSAMPLES; j++) {
      uint32_t s = crypto_rand_uint32();
      double p0 = random_uniform_01();
      unsigned n = sample_geometric(s, p0, p);

      if (n > PSI_DF)
        n = PSI_DF;
      C[n - 1]++;
    }

    if (psi_test(C, logP, NSAMPLES)) {
      if (++npass >= NPASSES_MIN)
        break;
    }
  }

  if (npass >= NPASSES_MIN) {
    /* printf("pass %s sampler\n", "geometric"); */
    return true;
  } else {
    printf("fail %s sampler\n", "geometric");
    return false;
  }
}

/**
 * Set logP[i] = log(F(x_i) - F(x_{i-1})), where x_-1 = -inf, x_n =
 * +inf, and x_i = i*(hi - lo)/(n - 2), and where F(x) is the CDF of
 * dist.
 */
static void
bin_cdfs(const struct dist *dist, double lo, double hi, double *logP, size_t n)
{
#define CDF(x)  dist->ops->cdf(dist, x)
#define SF(x)   dist->ops->sf(dist, x)
  const double w = (hi - lo)/(n - 2);
  double halfway = dist->ops->icdf(dist, 0.5);
  double x_0, x_1;
  size_t i;
  size_t n2 = get_size_t_from_double((halfway - lo)/w, false);

  assert(lo <= halfway);
  assert(halfway <= hi);
  assert(n2 <= n);

  x_1 = lo;
  logP[0] = log(CDF(x_1) - 0); /* 0 = CDF(-inf) */
  for (i = 1; i < n2; i++) {
    x_0 = x_1;
    x_1 = lo + i*w;
    logP[i] = log(CDF(x_1) - CDF(x_0));
  }
  x_0 = hi;
  logP[n - 1] = log(SF(x_0) - 0); /* 0 = SF(+inf) = 1 - CDF(+inf) */
  for (i = 1; i < n - n2; i++) {
    x_1 = x_0;
    x_0 = hi - i*w;
    logP[n - i - 1] = log(SF(x_0) - SF(x_1));
  }
#undef SF
#undef CDF
}

/**
 * Draw NSAMPLES samples from dist, counting the number of samples x in
 * the ith bin C[i] if x_{i-1} <= x < x_i, where x_-1 = -inf, x_n =
 * +inf, and x_i = i*(hi - lo)/(n - 2).
 */
static void
bin_samples(const struct dist *dist, double lo, double hi, size_t *C, size_t n)
{
  const double w = (hi - lo)/(n - 2);
  size_t i;

  for (i = 0; i < NSAMPLES; i++) {
    double x = dist->ops->sample(dist);
    size_t bin;

    if (x < lo)
      bin = 0;
    else if (x < hi)
      bin = 1 + get_size_t_from_double((x - lo)/w, true);
    else
      bin = n - 1;
    assert(bin < n);
    C[bin]++;
  }
}

/**
 * Sample NSAMPLES from dist, putting them in bins from -inf to lo to
 * hi to +inf, and apply up to two psi tests.  True if at least one psi
 * test passes; false if not.  False positive rate should be bounded by
 * 0.01^2 = 0.0001.
 */
static bool
test_psi_dist_sample(const struct dist *dist)
{
  double logP[PSI_DF] = {0};
  unsigned ntry = NTRIALS, npass = 0;
  double lo = dist->ops->icdf(dist, 1/(double)(PSI_DF + 2));
  double hi = dist->ops->isf(dist, 1/(double)(PSI_DF + 2));

  bin_cdfs(dist, lo, hi, logP, PSI_DF);
  while (ntry --> 0) {
    size_t C[PSI_DF] = {0};
    bin_samples(dist, lo, hi, C, PSI_DF);
    if (psi_test(C, logP, NSAMPLES)) {
      if (++npass >= NPASSES_MIN)
        break;
    }
  }
  if (npass >= NPASSES_MIN) {
    /* printf("pass %s sampler\n", dist->ops->name);*/
    return true;
  } else {
    printf("fail %s sampler\n", dist->ops->name);
    return false;
  }
}

static void
test_stochastic_uniform(void *arg)
{
  (void) arg;

  const struct uniform uniform01 = {
    .base = DIST_BASE(&uniform_ops),
    .a = 0,
    .b = 1,
  };
  const struct uniform uniform_pos = {
    .base = DIST_BASE(&uniform_ops),
    .a = 1.23,
    .b = 4.56,
  };
  const struct uniform uniform_neg = {
    .base = DIST_BASE(&uniform_ops),
    .a = -10,
    .b = -1,
  };
  const struct uniform uniform_cross = {
    .base = DIST_BASE(&uniform_ops),
    .a = -1.23,
    .b = 4.56,
  };
  const struct uniform uniform_subnormal = {
    .base = DIST_BASE(&uniform_ops),
    .a = 4e-324,
    .b = 4e-310,
  };
  const struct uniform uniform_subnormal_cross = {
    .base = DIST_BASE(&uniform_ops),
    .a = -4e-324,
    .b = 4e-310,
  };
  bool ok = true;

  ok &= test_psi_dist_sample(&uniform01.base);
  ok &= test_psi_dist_sample(&uniform_pos.base);
  ok &= test_psi_dist_sample(&uniform_neg.base);
  ok &= test_psi_dist_sample(&uniform_cross.base);
  ok &= test_psi_dist_sample(&uniform_subnormal.base);
  ok &= test_psi_dist_sample(&uniform_subnormal_cross.base);

  tt_assert(ok);

 done:
    ;
}

static bool
test_stochastic_logistic_impl(double mu, double sigma)
{
  const struct logistic dist = {
    .base = DIST_BASE(&logistic_ops),
    .mu = mu,
    .sigma = sigma,
  };

  /* XXX Consider some fancier logistic test.  */
  return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_log_logistic_impl(double alpha, double beta)
{
  const struct log_logistic dist = {
    .base = DIST_BASE(&log_logistic_ops),
    .alpha = alpha,
    .beta = beta,
  };

  /* XXX Consider some fancier log logistic test.  */
  return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_weibull_impl(double lambda, double k)
{
  const struct weibull dist = {
    .base = DIST_BASE(&weibull_ops),
    .lambda = lambda,
    .k = k,
  };

  /*
   * XXX Consider applying a Tiku-Singh test:
   *
   *    M.L. Tiku and M. Singh, `Testing the two-parameter
   *    Weibull distribution', Communications in Statistics --
   *    Theory and Methods A10(9), 1981, 907--918.
   *    https://www.tandfonline.com/doi/pdf/10.1080/03610928108828082?needAccess=true
   */
  return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_genpareto_impl(double mu, double sigma, double xi)
{
  const struct genpareto dist = {
    .base = DIST_BASE(&genpareto_ops),
    .mu = mu,
    .sigma = sigma,
    .xi = xi,
  };

  /* XXX Consider some fancier GPD test.  */
  return test_psi_dist_sample(&dist.base);
}

static void
test_stochastic_genpareto(void *arg)
{
  bool ok = 0;
  (void) arg;

  ok = test_stochastic_genpareto_impl(0, 1, -0.25);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(0, 1, -1e-30);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(0, 1, 0);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(0, 1, 1e-30);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(0, 1, 0.25);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(-1, 1, -0.25);
  tt_assert(ok);
  ok = test_stochastic_genpareto_impl(1, 2, 0.25);
  tt_assert(ok);

 done:
  ;
}

static void
test_stochastic_geometric(void *arg)
{
  bool ok = 0;
  (void) arg;

  ok = test_stochastic_geometric_impl(0.1);
  tt_assert(ok);
  ok = test_stochastic_geometric_impl(0.5);
  tt_assert(ok);
  ok = test_stochastic_geometric_impl(0.9);
  tt_assert(ok);
  ok = test_stochastic_geometric_impl(1);
  tt_assert(ok);

 done:
  ;
}

static void
test_stochastic_logistic(void *arg)
{
  bool ok = 0;
  (void) arg;

  ok = test_stochastic_logistic_impl(0, 1);
  tt_assert(ok);
  ok = test_stochastic_logistic_impl(0, 1e-16);
  tt_assert(ok);
  ok = test_stochastic_logistic_impl(1, 10);
  tt_assert(ok);
  ok = test_stochastic_logistic_impl(-10, 100);
  tt_assert(ok);

 done:
  ;
}

static void
test_stochastic_log_logistic(void *arg)
{
  bool ok = 0;
  (void) arg;

  ok = test_stochastic_log_logistic_impl(1, 1);
  tt_assert(ok);
  ok = test_stochastic_log_logistic_impl(1, 10);
  tt_assert(ok);
  ok = test_stochastic_log_logistic_impl(M_E, 1e-1);
  tt_assert(ok);
  ok = test_stochastic_log_logistic_impl(exp(-10), 1e-2);
  tt_assert(ok);

 done:
  ;
}

static void
test_stochastic_weibull(void *arg)
{
  bool ok = 0;
  (void) arg;

  ok = test_stochastic_weibull_impl(1, 0.5);
  tt_assert(ok);
  ok = test_stochastic_weibull_impl(1, 1);
  tt_assert(ok);
  ok = test_stochastic_weibull_impl(1, 1.5);
  tt_assert(ok);
  ok = test_stochastic_weibull_impl(1, 2);
  tt_assert(ok);
  ok = test_stochastic_weibull_impl(10, 1);
  tt_assert(ok);

 done:
  ;
}

struct testcase_t prob_distr_tests[] = {
  { "logit_logistics", test_logit_logistic, TT_FORK, NULL, NULL },
  { "log_logistic", test_log_logistic, TT_FORK, NULL, NULL },
  { "weibull", test_weibull, TT_FORK, NULL, NULL },
  { "genpareto", test_genpareto, TT_FORK, NULL, NULL },
  { "uniform_interval", test_uniform_interval, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

struct testcase_t slow_stochastic_prob_distr_tests[] = {
  { "stochastic_genpareto", test_stochastic_genpareto, TT_FORK, NULL, NULL },
  { "stochastic_geometric", test_stochastic_geometric, TT_FORK, NULL, NULL },
  { "stochastic_uniform", test_stochastic_uniform, TT_FORK, NULL, NULL },
  { "stochastic_logistic", test_stochastic_logistic, TT_FORK, NULL, NULL },
  { "stochastic_log_logistic", test_stochastic_log_logistic, TT_FORK, NULL,
    NULL },
  { "stochastic_weibull", test_stochastic_weibull, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
