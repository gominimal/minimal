use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "protos/streams.proto",
            "protos/tarball_format.proto",
            "protos/res/orchestrate_build.proto",
            "protos/res/create_env.proto",
            "protos/res/task.proto",
            "protos/res/remote_execution_service.proto",
        ],
        &["protos/", "protos/res"],
    )?;

    tonic_prost_build::configure()
        .compile_protos(&["protos/res/remote_execution_service.proto"], &["protos"])
        .unwrap();

    Ok(())
}
