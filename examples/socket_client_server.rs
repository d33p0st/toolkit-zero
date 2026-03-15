//! Demonstrates a typed HTTP server + client round-trip using the `socket` feature.
//!
//! Covers:
//!   - Building routes with [`ServerMechanism`] (plain, JSON body, query params, shared state,
//!     authenticated-encrypted body)
//!   - Registering routes with [`Server`]
//!   - Graceful server shutdown via a oneshot channel
//!   - Building a client with [`ClientBuilder`] and an explicit timeout
//!   - Issuing async requests (GET, POST+json, GET+query, POST+encrypted) with [`Client`]
//!   - The [`reply!`] macro for constructing responses
//!   - [`SerializationKey`] for authenticated-encrypted routes
//!
//! Run with:
//! ```sh
//! cargo run --example socket_client_server --features socket
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use bincode::{Encode, Decode};
use toolkit_zero::socket::SerializationKey;
use toolkit_zero::socket::server::{Server, ServerMechanism, Status, reply};
use toolkit_zero::socket::client::{ClientBuilder, Target};

// ─── Shared data types ────────────────────────────────────────────────────────

/// A simple item stored in the server's in-memory list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
struct Item {
    id:   u32,
    name: String,
}

/// Body for creating a new item.
#[derive(Debug, Deserialize, Serialize, Encode, Decode)]
struct NewItem {
    name: String,
}

/// Query parameters for filtering items.
#[derive(Debug, Deserialize, Serialize)]
struct Filter {
    prefix: String,
}

/// Response for a filtered search.
#[derive(Debug, Serialize, Deserialize)]
struct SearchResult {
    matches: Vec<Item>,
}

/// Simple health-check response.
#[derive(Debug, Serialize, Deserialize)]
struct Health {
    ok: bool,
}

const PORT: u16 = 19_876;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Build routes ──────────────────────────────────────────────────────────
    let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

    let mut server = Server::default();

    // Plain GET — no body, no state.
    server.mechanism(
        ServerMechanism::get("/health")
            .onconnect(|| async { reply!(json => Health { ok: true }) })
    );

    // POST with a JSON body — echoes back the created item.
    server.mechanism(
        ServerMechanism::post("/items")
            .json::<NewItem>()
            .onconnect(|body: NewItem| async move {
                reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
            })
    );

    // GET with query parameters — filters the stored items by prefix.
    server.mechanism({
        let store = store.clone();
        ServerMechanism::get("/items/search")
            .state(store)
            .query::<Filter>()
            .onconnect(|state: Arc<Mutex<Vec<Item>>>, f: Filter| async move {
                let items = state.lock().unwrap();
                let matches: Vec<Item> = items
                    .iter()
                    .filter(|i| i.name.starts_with(&f.prefix))
                    .cloned()
                    .collect();
                reply!(json => SearchResult { matches })
            })
    });

    // POST with shared state — stores the item and returns it.
    server.mechanism({
        let store = store.clone();
        ServerMechanism::post("/items/store")
            .state(store)
            .json::<NewItem>()
            .onconnect(|state: Arc<Mutex<Vec<Item>>>, body: NewItem| async move {
                let mut s = state.lock().unwrap();
                let id = s.len() as u32 + 1;
                let item = Item { id, name: body.name };
                s.push(item.clone());
                reply!(json => item, status => Status::Created)
            })
    });

    // POST with authenticated-encrypted body (ChaCha20-Poly1305 via SerializationKey).
    // The body is decrypted before the handler is called; a wrong key returns 403.
    server.mechanism(
        ServerMechanism::post("/items/secure")
            .encryption::<NewItem>(SerializationKey::Default)
            .onconnect(|body: NewItem| async move {
                let item = Item { id: 99, name: body.name };
                // The response must also be sealed so the client can open it.
                reply!(sealed => item, key => SerializationKey::Default)
            })
    );

    // ── Serve with graceful shutdown ──────────────────────────────────────────
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        server.serve_with_graceful_shutdown(
            ([127, 0, 0, 1], PORT),
            async { rx.await.ok(); },
        ).await;
    });

    // Give the server time to bind before firing requests.
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("Server started on port {PORT}");

    // ── Client requests ───────────────────────────────────────────────────────
    let client = ClientBuilder::new(Target::Localhost(PORT))
        .timeout(Duration::from_secs(5))
        .build_async();

    // GET /health
    let health: Health = client.get("/health").send().await?;
    assert!(health.ok);
    println!("GET  /health                → ok={}", health.ok);

    // POST /items (JSON body)
    let created: Item = client
        .post("/items")
        .json(NewItem { name: "widget".into() })
        .send()
        .await?;
    assert_eq!(created.name, "widget");
    println!("POST /items                 → {:?}", created);

    // POST /items/store (shared state — populates the store)
    let stored: Item = client
        .post("/items/store")
        .json(NewItem { name: "gadget".into() })
        .send()
        .await?;
    println!("POST /items/store           → {:?}", stored);

    let stored2: Item = client
        .post("/items/store")
        .json(NewItem { name: "gizmo".into() })
        .send()
        .await?;
    println!("POST /items/store           → {:?}", stored2);

    // GET /items/search?prefix=ga (query params)
    let result: SearchResult = client
        .get("/items/search")
        .query(Filter { prefix: "ga".into() })
        .send()
        .await?;
    assert!(result.matches.iter().all(|i| i.name.starts_with("ga")));
    println!("GET  /items/search?prefix=ga → {} match(es): {:?}", result.matches.len(), result.matches);

    // POST /items/secure (authenticated-encrypted body)
    let secure_item = client
        .post("/items/secure")
        .encryption(NewItem { name: "secret".into() }, SerializationKey::Default)
        .send::<Item>()
        .await?;
    assert_eq!(secure_item.name, "secret");
    println!("POST /items/secure          → {:?}", secure_item);

    // ── Shutdown ──────────────────────────────────────────────────────────────
    tx.send(()).ok();
    server_handle.await?;
    println!("\nAll requests successful ✓");
    Ok(())
}
