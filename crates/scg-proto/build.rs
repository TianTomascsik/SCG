//! Build script: compile the management protobuf into Rust gRPC client/server
//! stubs using `tonic-build` (which shells out to `protoc`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/scg_management.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/scg_management.proto");
    Ok(())
}
