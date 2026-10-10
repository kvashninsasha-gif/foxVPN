//! Release-test generator: writes only the public test matrix to stdout.
#[path = "../tests/support/startup_cases.rs"]
mod startup_cases;
fn main() {
    println!(
        "{}",
        serde_json::json!({"engine_version": env!("CARGO_PKG_VERSION"), "cases": startup_cases::cases()})
    );
}
