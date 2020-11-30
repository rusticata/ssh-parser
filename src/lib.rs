//!  This crate is implemented using the parser combinator [nom](https://github.com/Geal/nom).
//!
//!  The code is available on [GitHub](https://github.com/rusticata/ssh-parser)
//!  and is part of the [Rusticata](https://github.com/rusticata) project.

#[macro_use]
extern crate rusticata_macros;

#[macro_use]
extern crate nom;

#[cfg(feature = "serialize")]
#[macro_use]
extern crate cookie_factory;

#[cfg(feature = "integers")]
extern crate num_bigint;
#[cfg(feature = "integers")]
extern crate num_traits;

#[cfg(feature = "integers")]
pub mod mpint;
#[cfg(feature = "serialize")]
/// SSH packet crafting functions
pub mod serialize;
/// SSH parsing functions
pub mod ssh;

#[cfg(test)]
mod tests;

pub use ssh::*;
