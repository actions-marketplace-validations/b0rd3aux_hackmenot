// Test fixtures for Rust cryptography issues

// Should trigger RUST_CRY001
use md5;
use sha1;

fn test_weak_hashing() {
    use md5::{Md5, Digest};

    let data = b"hello world";
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
}

fn test_sha1_usage() {
    use sha1::{Sha1, Digest};

    let data = b"password123";
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
}
