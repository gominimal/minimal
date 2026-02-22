use std::io::Result;
fn main() -> Result<()> {
    tonic_prost_build::configure()
        .compile_protos(&["proto/min.proto"], &["proto"])
        .unwrap();
    Ok(())
}
