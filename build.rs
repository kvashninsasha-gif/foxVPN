use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=macos/platform.m");
    println!("cargo:rerun-if-changed=core/network-version.json");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let object = out.join("fox_platform.o");
        let library = out.join("libfox_platform.a");
        assert!(Command::new("xcrun")
            .args([
                "clang",
                "-fobjc-arc",
                "-mmacosx-version-min=13.0",
                "-c",
                "macos/platform.m",
                "-o"
            ])
            .arg(&object)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("ar")
            .arg("crs")
            .arg(library)
            .arg(object)
            .status()
            .unwrap()
            .success());
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=fox_platform");
        for framework in ["Foundation", "Security", "SystemConfiguration"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}
