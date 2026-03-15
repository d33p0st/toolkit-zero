
//! Convenience re-exports for the `socket` module.
//!
//! Importing this prelude brings the most commonly used server and client
//! types into scope through a single `use` path:
//!
//! ```rust,no_run
//! use toolkit_zero::socket::prelude::*;
//!
//! // Server types — fluent builder
//! let mut server = Server::default();
//! server.mechanism(ServerMechanism::get("/health").onconnect(|| async { reply!() }));
//!
//! // Server types — attribute macro shorthand
//! #[mechanism(server, GET, "/hello")]
//! async fn hello() { reply!() }
//!
//! // Client types
//! let client = Client::new(Target::Localhost(8080));
//! ```
//!
//! Re-exports are gated by feature flags:
//! - `socket-server` / `socket`: [`Server`], [`ServerMechanism`], [`Status`], [`mechanism`]
//! - `socket-client` / `socket`: [`Client`], [`ClientError`], [`Target`]
//! - always available: [`SerializationKey`]

pub use crate::socket::SerializationKey;

#[cfg(any(feature = "socket", feature = "socket-server"))]
pub use crate::socket::server::{Server, ServerMechanism, Status, mechanism};

#[cfg(any(feature = "socket", feature = "socket-client"))]
pub use crate::socket::client::{Client, ClientError, Target};