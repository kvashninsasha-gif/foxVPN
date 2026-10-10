//! Release-test generator: writes only the public test matrix to stdout.
#[path = "../tests/support/startup_cases.rs"]
mod startup_cases;
fn main() {
    println!(
        "{}",
        serde_json::to_string(&startup_cases::cases()).unwrap()
    );
}
