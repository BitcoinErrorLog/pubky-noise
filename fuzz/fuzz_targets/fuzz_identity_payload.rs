#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pubky_noise::identity_payload::{make_binding_message, BindingMessageParams, Role};

/// Arbitrary input for binding message generation
#[derive(Debug, Arbitrary)]
struct BindingMessageInput {
    pattern_tag: String,
    prologue: Vec<u8>,
    ed25519_pub: [u8; 32],
    local_noise_pub: [u8; 32],
    has_remote: bool,
    remote_noise_pub: [u8; 32],
    is_client: bool,
    has_server_hint: bool,
    server_hint: String,
}

fuzz_target!(|input: BindingMessageInput| {
    // Test that make_binding_message doesn't panic with arbitrary inputs
    let params = BindingMessageParams {
        pattern_tag: &input.pattern_tag,
        prologue: &input.prologue,
        ed25519_pub: &input.ed25519_pub,
        local_noise_pub: &input.local_noise_pub,
        remote_noise_pub: if input.has_remote {
            Some(&input.remote_noise_pub)
        } else {
            None
        },
        role: if input.is_client {
            Role::Client
        } else {
            Role::Server
        },
        server_hint: if input.has_server_hint {
            Some(input.server_hint.as_str())
        } else {
            None
        },
    };

    // Should never panic
    let _result = make_binding_message(&params);

    // Verify determinism: same inputs should produce same outputs
    let result2 = make_binding_message(&params);
    assert_eq!(_result, result2);
});

