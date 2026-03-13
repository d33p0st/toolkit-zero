
//! Convenience re-exports for the `socket` module.
//!
//! Importing this prelude brings the most commonly used server and client
//! types into scope through a single `use` path:
//!
//! ```rust,no_run
//! use toolkit_zero::socket::prelude::*;
//!
//! // Server types
//! let mut server = Server::default();
//! server.mechanism(ServerMechanism::get("/health").onconnect(|| async { reply!() }));
//!
//! // Client types
//! let client = Client::new(Target::Localhost(8080));
//! ```
//!
//! Re-exports are gated by feature flags: [`Server`], [`ServerMechanism`], and
//! [`Status`] are available under `socket-server`; [`Client`] and [`Target`]
//! are available under `socket-client`. Enabling `socket` provides both.

pub use crate::socket::SerializationKey;

#[cfg(any(feature = "socket", feature = "socket-server"))]
pub use crate::socket::server::{Server, ServerMechanism, Status};

#[cfg(any(feature = "socket", feature = "socket-client"))]
pub use crate::socket::client::{Client, ClientError, Target};