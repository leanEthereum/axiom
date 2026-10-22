//! A real scrape over a loopback socket.

use std::{future::Future, net::SocketAddr, time::Duration};

use axiom_http::{Client, ClientConfig, Endpoint, Method, Request, StatusCode};
use axiom_telemetry::{CONTENT_TYPE, MetricsServer, NodeMetrics, Registry};
use tokio::sync::oneshot;

/// Runs a test body on a single-threaded runtime with timers and sockets.
fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(test);
}

#[test]
fn scrape_returns_the_registry() {
    run(async {
        // The node metric set, with a few values a dashboard would show.
        let registry = Registry::new();
        let metrics = NodeMetrics::register(&registry).unwrap();
        metrics.head_slot.set(12_345);
        metrics
            .gossip_messages
            .with_label_values(["beacon_block", "accept"])
            .inc();

        // Port zero picks a free port; the server reports which.
        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = MetricsServer::bind(address, registry.clone())
            .await
            .unwrap();
        let bound = server.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server.serve(async {
            let _ = stopped.await;
        }));

        // A client on the bound address.
        let endpoint = Endpoint::parse(&format!("http://{bound}")).unwrap();
        let config = ClientConfig {
            request_timeout: Duration::from_secs(2),
            ..ClientConfig::default()
        };
        let client = Client::new(endpoint, config);

        // The scrape answers 200 with the versioned text media type.
        let response = client
            .send(&Request::new(Method::Get, "/metrics"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers.get("content-type"), Some(CONTENT_TYPE));

        // The body is the registry text at that instant.
        let body = String::from_utf8(response.body).unwrap();
        assert_eq!(body, registry.render());
        assert!(body.contains("\nbeacon_head_slot 12345\n"));
        assert!(
            body.contains("\ngossip_messages_total{topic=\"beacon_block\",outcome=\"accept\"} 1\n")
        );

        // Any other path is not served.
        let response = client
            .send(&Request::new(Method::Get, "/other"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        // Shut down and wait for the drain.
        let _ = stop.send(());
        task.await.unwrap();
    });
}
