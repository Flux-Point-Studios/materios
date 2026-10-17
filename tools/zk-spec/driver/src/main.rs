use materios_zk_core::{activation, bridge};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
    process::{Command, ExitCode},
};

fn execute(program: &str, args: &[&str]) -> Result<Value, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("{program} emitted invalid observations: {e}"))
}

fn python(operation: &str) -> Result<Value, String> {
    execute("python3", &["tools/zk-spec/p0_tools.py", operation])
}

fn bridge_codec() -> Result<Value, String> {
    let aiken = execute("aiken", &["check", "--deny", "tools/zk-spec/aiken"])?;
    let tests = aiken["modules"]
        .as_array()
        .ok_or("missing Aiken modules")?
        .iter()
        .flat_map(|m| m["tests"].as_array().into_iter().flatten())
        .collect::<Vec<_>>();
    if tests.len() != 9 || aiken["summary"]["total"] != 9 || aiken["summary"]["failed"] != 0 {
        return Err("Aiken evaluator did not run all nine checks".into());
    }
    let mut cases = Vec::new();
    for (name, recipient) in [
        ("account_roundtrip", bridge::Recipient::Account([0x11; 32])),
        ("utxo_roundtrip", bridge::Recipient::Utxo([0x22; 32])),
    ] {
        let bytes = bridge::encode(recipient);
        cases.push(json!({"case": name, "cbor": hex::encode(&bytes), "rust_accepted": bridge::decode(&bytes) == Ok(recipient)}));
    }
    let account = bridge::encode(bridge::Recipient::Account([0x11; 32]));
    for (name, bytes) in [
        ("rejects_reserved", {
            let mut b = account.clone();
            b[3] = 2;
            b
        }),
        ("rejects_unknown_variant", {
            let mut b = account.clone();
            b[3] = 3;
            b
        }),
        ("rejects_unknown_version", {
            let mut b = account.clone();
            b[1] = 2;
            b
        }),
        ("rejects_short_key", {
            let mut b = account.clone();
            b[5] = 31;
            b.pop();
            b
        }),
        ("rejects_trailing_bytes", {
            let mut b = account.clone();
            b.push(0);
            b
        }),
        ("rejects_noncanonical_integer", {
            let mut b = account.clone();
            b.insert(1, 0x18);
            b
        }),
        ("rejects_unknown_lock", {
            let mut b = bridge::encode(bridge::Recipient::Utxo([0x22; 32]));
            b[5] = 1;
            b
        }),
    ] {
        cases.push(json!({"case": name, "cbor": hex::encode(&bytes), "rust_accepted": bridge::decode(&bytes).is_ok()}));
    }
    for case in &mut cases {
        let name = case["case"].as_str().ok_or("missing case name")?;
        let matching: Vec<_> = tests.iter().filter(|t| t["title"] == name).collect();
        if matching.len() != 1 {
            return Err(format!("missing or duplicate Aiken case {name}"));
        }
        case["aiken_assertion_passed"] = json!(matching[0]["status"] == "pass");
        case["aiken_execution_units"] = matching[0]["execution_units"].clone();
    }
    Ok(json!({"cases": cases, "aiken_summary": aiken["summary"], "rust_codec": "materios-zk-core"}))
}

fn operation(name: &str, payload: &Value) -> Result<Value, String> {
    match name {
        "p0-mainnet-refusal" => {
            let inventory = python("chain-targets")?;
            let targets = inventory["mainnet"].as_array().ok_or("missing mainnet targets")?;
            if targets.is_empty() { return Err("empty mainnet target inventory".into()); }
            let mut cases = Vec::new();
            for target in targets.iter().chain(inventory["preprod"].as_array().ok_or("missing preprod targets")?).chain(std::iter::once(&inventory["file_alias_probe"])) {
                let route=target["route"].as_str().ok_or("missing source route")?;
                let id=target["id"].as_str().ok_or("missing chain id")?;
                cases.push(json!({"target": target, "allowed": activation::enable(route,id).is_ok()}));
            }
            Ok(json!({"inventory": inventory, "cases": cases, "mutants": python("refusal-mutants")?}))
        }
        "p0-core-no-egress" => python("core-no-egress"),
        "p0-midnight-negative-control" => python("midnight-negative-control"),
        "p0-metadata-compat" => python("metadata-compat"),
        "p0-bridge-codec" => bridge_codec(),
        "p0-sapling-spike" => {
            let provenance = Command::new("python3").args(["tools/zk-spec/vectors.py", "--check"]).output().map_err(|e| e.to_string())?;
            if !provenance.status.success() { return Err(format!("public corpus provenance failed: {}", String::from_utf8_lossy(&provenance.stderr))); }
            let build = Command::new("nice").args(["-n", "10", "cargo", "+1.85.0", "build", "--offline", "--locked", "--release", "--no-default-features", "--target", "wasm32-unknown-unknown", "--manifest-path", "tools/zk-spec/wasm/Cargo.toml"]).output().map_err(|e| e.to_string())?;
            if !build.status.success() { return Err(format!("no_std Wasm build failed: {}", String::from_utf8_lossy(&build.stderr))); }
            let wasm = ".zk-spec-target/wasm32-unknown-unknown/release/materios_zk_wasm.wasm";
            if !Path::new(wasm).is_file() { return Err("no_std Sapling Wasm build artifact missing; run setup".into()); }
            let mut result = execute("node", &["tools/zk-spec/wasm-run.mjs", wasm])?;
            result["macbook"] = python("macbook-observation")?;
            let mut sources = serde_json::Map::new();
            for file in ["Cargo.lock", "core/Cargo.toml", "core/src/lib.rs", "core/src/sapling.rs", "wasm/Cargo.toml", "wasm/src/lib.rs", "wasm-run.mjs", "fixtures/actions.bin", "fixtures/bundles.bin", "fixtures/provenance.json"] {
                let data = std::fs::read(format!("tools/zk-spec/{file}")).map_err(|e| e.to_string())?;
                sources.insert(file.into(), json!(hex::encode(Sha256::digest(data))));
            }
            result["source_sha256"] = Value::Object(sources);
            let compiler = Command::new("rustc").args(["+1.85.0", "--version"]).output().map_err(|e| e.to_string())?;
            if !compiler.status.success() { return Err("compiler identity unavailable".into()); }
            let compiler_text = String::from_utf8(compiler.stdout).map_err(|e| e.to_string())?;
            let version = compiler_text.split_whitespace().nth(1).ok_or("compiler version missing")?;
            if version != "1.85.0" { return Err("unexpected Sapling compiler".into()); }
            result["rustc"] = json!(version);
            result["target"] = json!("wasm32-unknown-unknown");
            result["build_flags"] = json!(["--locked", "--offline", "--release", "--no-default-features"]);
            std::fs::create_dir_all("tools/zk-spec/artifacts").map_err(|e| e.to_string())?;
            std::fs::write("tools/zk-spec/artifacts/spike-gemtek.json", result.to_string()).map_err(|e| e.to_string())?;
            Ok(result)
        }
        _ => Err(format!("operation {name} has no implemented production path/artifact in P0; later-phase runtime evidence remains required (payload fields: {})", payload.as_object().map_or(0, |p| p.len()))),
    }
}

fn main() -> ExitCode {
    let result = (|| -> Result<Value, String> {
        let mut input = String::new();
        io::stdin()
            .take(1_048_577)
            .read_to_string(&mut input)
            .map_err(|e| e.to_string())?;
        if input.len() > 1_048_576 {
            return Err("request too large".into());
        }
        let request: Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
        let fields = request.as_object().ok_or("request must be an object")?;
        if fields.len() != 3
            || request["version"].as_u64() != Some(1)
            || !request["payload"].is_object()
        {
            return Err("invalid request protocol".into());
        }
        let result = operation(
            request["operation"].as_str().ok_or("missing operation")?,
            &request["payload"],
        )?;
        Ok(json!({"version":1,"result":result}))
    })();
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
