fn main() {
    #[cfg(feature = "std")]
    {
        let mut builder = substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .import_memory()
            .export_heap_base();
        println!("cargo:rerun-if-env-changed=CARGO_HOME");
        for (directory, name) in build_directories() {
            builder =
                builder.append_to_rust_flags(format!("--remap-path-prefix={directory}={name}"));
        }
        builder.build();
    }
}

/// The directories the blob's sources come from, each with the name the blob
/// gives it instead, so that the blob, and every genesis built from it, does
/// not depend on where it was built: panic messages carry source paths. The
/// last matching remap wins, so a Cargo home or toolchain kept inside the
/// repository still gets its own name.
#[cfg(feature = "std")]
fn build_directories() -> [(String, &'static str); 3] {
    use std::{env, path::Path, process::Command};
    let repository = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"))
        .ancestors()
        .nth(2)
        .expect("the runtime sits two levels below the repository root")
        .display()
        .to_string();
    let cargo_home = env::var("CARGO_HOME").unwrap_or_else(|_| {
        format!(
            "{}/.cargo",
            env::var("HOME").expect("CARGO_HOME or HOME is set")
        )
    });
    let sysroot = Command::new(env::var("RUSTC").expect("cargo sets it"))
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc prints its sysroot");
    let sysroot = String::from_utf8(sysroot.stdout)
        .expect("the sysroot is UTF-8")
        .trim()
        .to_owned();
    [
        (repository, "/materios"),
        (cargo_home, "/cargo-home"),
        (sysroot, "/rust-toolchain"),
    ]
}
