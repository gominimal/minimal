use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &["protos/injected_files.proto", "protos/tarball_format.proto"],
        &["protos/"],
    )?;
    Ok(())
}
