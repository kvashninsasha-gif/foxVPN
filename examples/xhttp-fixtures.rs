//! Public transport fixtures only; never opens the user's Vault or GUI.
#[cfg(feature = "test-support")]
fn main() {
    use std::io::{BufRead, Write};
    let args: Vec<String> = std::env::args().collect();
    let server = smart_vpn_engine::servers::Server::parse(&args[2]).expect("public test URI");
    if args[1] == "config" {
        let port: u16 = args[3].parse().unwrap();
        println!(
            "{}",
            smart_vpn_engine::xhttp::configuration(&server, port, "public-fixture-password")
                .unwrap()
        );
    } else if args[1] == "engine" {
        let settings = smart_vpn_engine::settings::Settings {
            tun: false,
            kill_switch: false,
            mode: smart_vpn_engine::routing::Mode::Vpn,
            ..Default::default()
        };
        let mut core = smart_vpn_engine::vpn::CoreProcess::start(
            std::path::Path::new(&args[3]),
            &server,
            &settings,
            &[smart_vpn_engine::routing::Rule {
                domain: "127.0.0.1".into(),
                route: "vpn".into(),
            }],
        )
        .expect("fixture start");
        println!(
            "{}",
            serde_json::json!({"proxy_port":core.proxy_port,"transport_port":core.transport_proxy_port()})
        );
        std::io::stdout().flush().unwrap();
        for line in std::io::stdin().lock().lines() {
            if line.unwrap() == "status" {
                println!("{}", core.alive());
                std::io::stdout().flush().unwrap();
            } else {
                break;
            }
        }
        core.stop_checked().expect("fixture stop");
    } else {
        panic!("unknown fixture mode");
    }
}
#[cfg(not(feature = "test-support"))]
fn main() {
    panic!("Requires test-support; never uses an installed profile")
}
