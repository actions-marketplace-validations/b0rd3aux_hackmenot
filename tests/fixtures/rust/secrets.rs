// Test fixtures for hardcoded secrets in Rust

fn test_hardcoded_credentials() {
    // Should trigger RUST_SEC001
    let api_key = "sk-1234567890abcdef";
    let password = "admin123";
    let secret = "my-secret-key";
    let access_key = "AKIAIOSFODNN7EXAMPLE";

    connect_to_api(api_key);
}

fn connect_to_api(key: &str) {
    // API connection logic
}

struct Config {
    // Should trigger RUST_SEC001
    api_key: String,
    private_key: String,
}
