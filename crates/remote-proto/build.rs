use std::io::Result;

fn main() -> Result<()> {
    let mut includes: Vec<String> = vec!["protos/".into(), "protos/res".into()];
    if let Ok(dir) = std::env::var("PROTOC_INCLUDE") {
        includes.push(dir);
    }
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    let include_paths: Vec<&str> = includes.iter().map(String::as_str).collect();

    let proto_files = &[
        "protos/streams.proto",
        "protos/tarball_format.proto",
        "protos/res/orchestrate_build.proto",
        "protos/res/create_env.proto",
        "protos/res/download.proto",
        "protos/res/task.proto",
        "protos/res/check.proto",
        "protos/res/remote_execution_service.proto",
    ];
    for f in proto_files {
        println!("cargo:rerun-if-changed={f}");
    }

    prost_build::compile_protos(proto_files, &include_paths)?;

    tonic_prost_build::configure()
        .compile_protos(
            &["protos/res/remote_execution_service.proto"],
            &include_paths,
        )
        .unwrap();

    Ok(())
}
