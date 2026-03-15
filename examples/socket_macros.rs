//! Demonstrates the `#[mechanism]` and `#[request]` attribute macros for the
//! `socket` feature alongside the new `.background()` method on [`ServerFuture`].
//!
//! The `#[mechanism]` macro is a concise alternative to building a
//! [`ServerMechanism`] manually — it expands to a `server.mechanism(…)` call
//! and infers the method, path, optional body/query/state/encryption modifier,
//! and handler function in a single line.
//!
//! The `#[request]` macro is the corresponding client-side shorthand: it sends
//! an HTTP request via a [`Client`] and binds the decoded response to a local
//! variable sharing the function name.
//!
//! Using `.background()` on a [`ServerFuture`] spawns the hyper-based server
//! as a Tokio background task, returning a [`tokio::task::JoinHandle`] immediately
//! so that the example can keep running client code while the server is up.
//!
//! Covers:
//!   - `#[mechanism(server, GET, path)]`                — plain handler, no body
//!   - `#[mechanism(server, POST, path, json)]`         — JSON-decoded body
//!   - `#[mechanism(server, GET, path, query)]`         — URL query parameters
//!   - `#[mechanism(server, POST, path, state(…), json)]` — shared state + JSON
//!   - `#[mechanism(server, POST, path, encrypted(…))]` — AEAD-encrypted body
//!   - `#[request(client, GET,  path, async)]`          — async GET
//!   - `#[request(client, POST, path, json(…), async)]`        — async POST+JSON
//!   - `#[request(client, GET,  path, query(…), async)]`       — async GET+query
//!   - `#[request(client, POST, path, encrypted(…), async)]`   — async POST+AEAD
//!   - `ServerFuture::background()`                            — non-blocking start
//!
//! Run with:
//! ```sh
//! cargo run --example socket_macros --features socket
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use bincode::{Encode, Decode};

use toolkit_zero::socket::SerializationKey;
use toolkit_zero::socket::server::{Server, Status, reply, mechanism};
use toolkit_zero::socket::client::{ClientBuilder, Target, request};

// ─── Data types ──────────────────────────────────────────────────────────────

/// A stored item with an id and a name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
struct Item {
    id:   u32,
    name: String,
}

/// Request body for creating a new item.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct NewItem {
    name: String,
}

/// URL query parameters for searching items by name prefix.
#[derive(Debug, Serialize, Deserialize)]
struct Filter {
    prefix: String,
}

/// A list of items returned by the search route.
#[derive(Debug, Serialize, Deserialize)]
struct SearchResult {
    matches: Vec<Item>,
}

/// Response body for the health-check endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct Health {
    ok: bool,
}

const PORT: u16 = 19_877;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));
    let mut server = Server::default();

    // ── Register routes via #[mechanism] ────────────────────────────────────
    //
    // Each attribute expands to:
    //   server.mechanism(ServerMechanism::METHOD(path)[.modifier()].onconnect(fn));

    // Plain GET — no body, no state.
    #[mechanism(server, GET, "/health")]
    async fn health_handler() {
        reply!(json => Health { ok: true })
    }

    // POST + JSON body — returns the created item.
    #[mechanism(server, POST, "/items", json)]
    async fn create_item(body: NewItem) {
        reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
    }

    // GET + query params — echoes back the search prefix.
    // (Filtered search requires access to the store; see /items/store below.)
    #[mechanism(server, GET, "/items/search", state(store.clone()), query)]
    async fn search_items(state: Arc<Mutex<Vec<Item>>>, f: Filter) {
        let items = state.lock().unwrap();
        let matches: Vec<Item> = items
            .iter()
            .filter(|i| i.name.starts_with(&f.prefix))
            .cloned()
            .collect();
        reply!(json => SearchResult { matches })
    }

    // POST + shared state + JSON body — persists the item.
    #[mechanism(server, POST, "/items/store", state(store.clone()), json)]
    async fn store_item(state: Arc<Mutex<Vec<Item>>>, body: NewItem) {
        let mut s = state.lock().unwrap();
        let id = s.len() as u32 + 1;
        let item = Item { id, name: body.name };
        s.push(item.clone());
        reply!(json => item, status => Status::Created)
    }

    // POST + AEAD-encrypted body (ChaCha20-Poly1305 via SerializationKey).
    // The body is decrypted before the handler is called; the response is
    // sealed so the client's `.send::<Item>()` can open it automatically.
    #[mechanism(server, POST, "/items/secure", encrypted(SerializationKey::Default))]
    async fn secure_create(body: NewItem) {
        let item = Item { id: 99, name: body.name };
        reply!(sealed => item, key => SerializationKey::Default)
    }

    // ── Start the server in the background via .background() ────────────────
    //
    // Previously this required manually wrapping the `.await` call inside
    // `tokio::spawn(async move { server.serve_*(…).await; })`.
    // `.background()` is the idiomatic shorthand for exactly that pattern.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = server
        .serve_with_graceful_shutdown(
            ([127, 0, 0, 1], PORT),
            async { rx.await.ok(); },
        )
        .background();                               // ← non-blocking spawn

    // Give the server a moment to bind before firing requests.
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("Server started on port {PORT}");

    // ── Issue all requests via #[request] ───────────────────────────────────
    //
    // Each attribute expands to an expression that sends the request and awaits
    // the response, binding the decoded value to a local with the function name.

    let client = ClientBuilder::new(Target::Localhost(PORT))
        .timeout(Duration::from_secs(5))
        .build_async();

    // Async GET /health — plain request, no body.
    #[request(client, GET, "/health", async)]
    async fn health_resp() -> Health {}
    assert!(health_resp.ok);
    println!("GET  /health                → ok={}", health_resp.ok);

    // Async POST /items — JSON body.
    #[request(client, POST, "/items", json(NewItem { name: "widget".to_string() }), async)]
    async fn created() -> Item {}
    assert_eq!(created.name, "widget");
    println!("POST /items                 → {:?}", created);

    // Store a couple of items so the search route has data.
    #[request(client, POST, "/items/store", json(NewItem { name: "gadget".to_string() }), async)]
    async fn stored1() -> Item {}
    println!("POST /items/store           → {:?}", stored1);

    #[request(client, POST, "/items/store", json(NewItem { name: "gizmo".to_string() }), async)]
    async fn stored2() -> Item {}
    println!("POST /items/store           → {:?}", stored2);

    // Async GET /items/search?prefix=ga — query params with shared state.
    #[request(client, GET, "/items/search", query(Filter { prefix: "ga".to_string() }), async)]
    async fn results() -> SearchResult {}
    assert!(results.matches.iter().all(|i| i.name.starts_with("ga")));
    println!(
        "GET  /items/search?prefix=ga → {} match(es): {:?}",
        results.matches.len(),
        results.matches
    );

    // Async POST /items/secure — AEAD-encrypted body.
    #[request(client, POST, "/items/secure", encrypted(NewItem { name: "secret".to_string() }, SerializationKey::Default), async)]
    async fn secure_item() -> Item {}
    assert_eq!(secure_item.name, "secret");
    println!("POST /items/secure          → {:?}", secure_item);

    // ── Graceful shutdown ───────────────────────────────────────────────────
    tx.send(()).ok();
    server_handle.await?;
    println!("\nAll requests successful ✓");
    Ok(())
}
