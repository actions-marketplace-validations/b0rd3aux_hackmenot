// Test fixtures for Rust unsafe operations
use std::ptr;
use std::mem;

fn test_unsafe_block() {
    let x = 42;
    let ptr = &x as *const i32;

    // Should trigger RUST_UNS001
    unsafe {
        let value = *ptr;
        println!("Value: {}", value);
    }
}

fn test_raw_pointer_ops() {
    let mut data = vec![1, 2, 3, 4];
    let ptr = data.as_mut_ptr();

    // Should trigger RUST_UNS002
    unsafe {
        ptr::write(ptr, 42);
        let value = ptr::read(ptr);
        let offset_ptr = ptr.offset(1);
    }
}

fn test_transmute() {
    let x: u32 = 0x12345678;

    // Should trigger RUST_UNS003
    unsafe {
        let bytes: [u8; 4] = mem::transmute(x);
        println!("{:?}", bytes);
    }
}

// Should trigger RUST_UNS001
unsafe fn unsafe_function() {
    // This entire function is unsafe
}

fn test_command_injection(user_input: &str) {
    use std::process::Command;

    // Should trigger RUST_INJ002
    Command::new("ls")
        .arg(user_input)
        .spawn()
        .expect("failed to execute");
}
