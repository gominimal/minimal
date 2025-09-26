fn main() {
    tonic_prost_build::configure()
        .compile_protos(&["proto/service.proto"], &["proto"])
        .unwrap();
}
