use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "protos/injected_files.proto",
            "protos/tarball_format.proto",
            "protos/command_parameters.proto",
            "protos/create_build.proto",
            "protos/poll_build.proto",
            "protos/upload.proto",
            "protos/remote_execution_service.proto",
        ],
        &["protos/"],
    )?;

    tonic_prost_build::configure()
        .compile_protos(&["protos/remote_execution_service.proto"], &["protos"])
        .unwrap();

    Ok(())
}
