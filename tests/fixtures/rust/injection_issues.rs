// Test fixtures for Rust injection vulnerabilities

fn test_sql_injection(user_id: &str) {
    // Should trigger RUST_INJ001
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    println!("{}", query);

    let update = format!("UPDATE users SET name = '{}' WHERE id = 1", user_id);
    println!("{}", update);
}

fn test_string_formatting_sql() {
    let user_input = "malicious'; DROP TABLE users--";

    // Should trigger RUST_INJ001
    println!("SELECT * FROM products WHERE name = '{}'", user_input);
}
