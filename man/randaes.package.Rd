\name{randaes-package}
\alias{randaes-package}
\alias{randaes}
\docType{package}
\title{
Random number generator based on AES cipher.
}
\description{
This package implements the deterministic part of the Fortuna
cryptographic PRNG described in "Practical Crytography" by Ferguson and
Schneier. It does not implement the entropy accumulators needed for
secure cryptographic use and is intended for statistical simulation.
}
\details{
\tabular{ll}{
Package: \tab randaes\cr
Type: \tab Package\cr
Version: \tab 0.1\cr
Date: \tab 2005-08-25\cr
License: \tab GPL 2
}
After loading the package, \code{RNGkind("user")} will use the
generator.

The generator encrypts a 128-bit counter using 256-bit AES, resetting
the key after \eqn{2^{16}}{2^16} encryptions to minimise information leakage
from lack of collisions.  Each 128-bit result is used to provide two
U[0,1] numbers, which thus have the full 53 bits of variability
representable in double precision.

Because of the encryption step and the use of 64 bit rather than 32 bit
results, this generator is 50-100\% slower than the built-in Mersenne
Twister.  Ferguson and Schneier argue that any computation
distinguishing the output of this generator from genuinely random
numbers in less than \eqn{2^{113}}{2^113} operations implies an attack on the
underlying cipher [or, much more likely, a bug in the implementation],
so the generator should be particularly useful for rechecking the
results of surprising simulations.

}
\author{
Thomas Lumley, using AES code by Christophe Devine
}
\references{
Ferguson N, Schneier B. (2003) Practical Cryptography. John Wiley \& Sons.

National Institute of Standard and Technology (2001). "Advanced
Encryption Standard". Federal Information Processing Standard 197.
}
\keyword{ package }
\seealso{\code{\link{Random.user}}, \code{\link{RNGkind}}
}
\examples{
RNGkind("user")
set.seed(42)
runif(10)

## generates random integers in blocks of 4
.C("fortuna_ints", as.integer(6), integer(6))
}
