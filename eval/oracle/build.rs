fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/zone.proto");
    println!("cargo:rerun-if-changed=proto/container.proto");
    println!("cargo:rerun-if-changed=proto/image.proto");

    tonic_build::configure()
        .build_server(false)
        .client_mod_attribute(
            ".",
            "#[allow(clippy::mixed_attributes_style, clippy::result_large_err)]",
        )
        .compile_protos(
            &[
                "proto/zone.proto",
                "proto/container.proto",
                "proto/image.proto",
            ],
            &["proto/"],
        )?;
    Ok(())
}
