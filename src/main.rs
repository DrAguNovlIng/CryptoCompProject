use std::collections::HashMap;



fn main() {
    let mut shared_values = HashMap::new();

    shared_values.insert("a", 1);

    match shared_values.get_key_value("a") {
        Some((k,v)) => println!("Found the key: {} which has value: {}", k, v),
        None => println!("Not found"),
    }
}
