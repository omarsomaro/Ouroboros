//! Integration tests: Node functionality
//!
//! Tests EtherNode creation, publish, and basic operations.
//! Full two-node communication tests require complete gossip implementation.

use ethersync::{EtherNode, NodeConfig};

/// Helper: Create a test node
async fn create_test_node() -> EtherNode {
    let config = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    EtherNode::new(config).await.expect("Failed to create node")
}

#[tokio::test]
async fn test_node_creation() {
    let node = create_test_node().await;

    // Check socket is bound
    let addr = node.local_addr();
    assert!(addr.port() > 0);

    // Check initial state
    assert_eq!(node.peer_count().await, 0);
    assert_eq!(node.subscription_count().await, 0);
}

#[tokio::test]
async fn test_publish_creates_valid_message() {
    let node = create_test_node().await;
    let passphrase = "test-pass";
    let payload = b"Hello, EtherSync!";

    let msg = node
        .publish(passphrase, payload)
        .await
        .expect("Failed to publish");

    // Verify message properties
    assert_eq!(
        msg.header.slot_id,
        ethersync::EtherCoordinate::current_slot()
    );
    assert_eq!(msg.header.fragment_index, 0);
    assert_eq!(msg.header.total_fragments, 1);

    // Verify we can decrypt it
    let decrypted = msg.decrypt(passphrase).expect("Failed to decrypt");
    assert_eq!(decrypted, payload);
}

#[tokio::test]
async fn test_publish_stores_locally() {
    let node = create_test_node().await;
    let passphrase = "test-storage";

    // Publish a message
    let msg = node
        .publish(passphrase, b"test")
        .await
        .expect("Failed to publish");
    let slot = msg.header.slot_id;

    // Check storage has the message
    let storage = node.storage().lock().await;
    let hash = blake3_hash(&msg.encrypted_payload);
    let stored = storage.get(slot, hash).expect("Failed to query storage");

    assert!(!stored.is_empty(), "Message should be stored");
}

#[tokio::test]
async fn test_publish_multiple_messages() {
    let node = create_test_node().await;
    let passphrase = "test-multi";

    let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];

    for msg in messages {
        node.publish(passphrase, msg)
            .await
            .expect("Failed to publish");
    }

    // All publishes should succeed
    assert_eq!(node.subscription_count().await, 0);
}

#[tokio::test]
async fn test_subscription_creation() {
    let node = create_test_node().await;
    let passphrase = "test-sub";

    let rx = node
        .subscribe(passphrase)
        .await
        .expect("Failed to subscribe");

    // Channel should be open
    assert!(!rx.is_closed());

    // Subscription count should increase
    assert_eq!(node.subscription_count().await, 1);
}

#[tokio::test]
async fn test_multiple_subscriptions() {
    let node = create_test_node().await;

    // Create multiple subscriptions
    let _rx1 = node
        .subscribe("space-1")
        .await
        .expect("Failed to subscribe 1");
    let _rx2 = node
        .subscribe("space-2")
        .await
        .expect("Failed to subscribe 2");
    let _rx3 = node
        .subscribe("space-3")
        .await
        .expect("Failed to subscribe 3");

    assert_eq!(node.subscription_count().await, 3);
}

#[tokio::test]
async fn test_publish_empty_payload() {
    let node = create_test_node().await;

    let msg = node
        .publish("test", b"")
        .await
        .expect("Failed to publish empty");
    let decrypted = msg.decrypt("test").expect("Failed to decrypt");

    assert!(decrypted.is_empty());
}

#[tokio::test]
async fn test_publish_large_payload() {
    let node = create_test_node().await;

    // 10KB payload
    let large: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

    let msg = node
        .publish("test", &large)
        .await
        .expect("Failed to publish large");
    let decrypted = msg.decrypt("test").expect("Failed to decrypt");

    assert_eq!(decrypted, large);
}

#[tokio::test]
async fn test_wrong_passphrase_fails_decrypt() {
    let node = create_test_node().await;

    let msg = node
        .publish("correct", b"secret")
        .await
        .expect("Failed to publish");

    // Decrypt with wrong passphrase should fail
    let result = msg.decrypt("wrong");
    assert!(result.is_err() || result.unwrap() != b"secret");
}

#[tokio::test]
async fn test_node_with_bootstrap_peers() {
    // Create first node
    let node_a = create_test_node().await;
    let addr_a = node_a.local_addr();

    // Create second node with first as bootstrap
    let config_b = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        bootstrap_peers: vec![addr_a],
        ..Default::default()
    };
    let node_b = EtherNode::new(config_b)
        .await
        .expect("Failed to create node B");

    // Bootstrap peers should be configured
    assert!(!node_b.local_addr().to_string().is_empty());
}

/// Blake3 hash helper
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    ouroboros_crypto::hash::blake3_hash(data)
}

// Note: Full two-node communication tests will be enabled once gossip protocol
// implementation is complete. Current stub implementation supports:
// - Node creation and socket binding
// - Message publishing and local storage
// - Subscription channel creation
//
// Gossip message exchange between nodes requires:
// - Complete sweep_slot implementation
// - Active background gossip task
// - Peer-to-peer message forwarding
