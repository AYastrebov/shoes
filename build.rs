//! Protocol codegen for the privileged daemon.
//!
//! Only under `--features daemon`. Every other build -- the CLI, both mobile
//! artifacts, a library consumer -- does nothing here, and `tonic-prost-build`
//! is an optional build dependency so those builds do not compile it either.
//!
//! This needs `protoc` on the build machine. `prost-build` stopped vendoring
//! one, so it is an install step rather than a crate: `brew install protobuf`
//! on macOS, and the release workflow does the same before it builds `shoesd`.

#[cfg(not(feature = "daemon"))]
fn main() {}

#[cfg(feature = "daemon")]
fn main() {
    // The client half is generated too, and it is not dead weight: it is what
    // the tests speak to the socket, so the peer-credential check and the
    // error mapping are exercised over a real connection rather than by
    // calling the service struct directly. The shipping consumer generates its
    // own client in Kotlin from a vendored copy of this file.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/shoes/daemon/v1/daemon.proto"], &["proto"])
        .expect("failed to compile proto/shoes/daemon/v1/daemon.proto");

    println!("cargo:rerun-if-changed=proto/shoes/daemon/v1/daemon.proto");
}
