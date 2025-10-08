fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf files using tonic-prost-build
    tonic_prost_build::compile_protos("proto/events.proto")?;

    // Re-run build script if proto files change
    println!("cargo:rerun-if-changed=proto/events.proto");

    Ok(())
}
