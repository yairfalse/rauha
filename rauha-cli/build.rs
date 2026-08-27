fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .client_mod_attribute(
            ".",
            "#[allow(clippy::mixed_attributes_style, clippy::result_large_err)]",
        )
        .compile_protos(
            &[
                "../proto/zone.proto",
                "../proto/container.proto",
                "../proto/image.proto",
                "../proto/sandbox.proto",
            ],
            &["../proto"],
        )?;
    Ok(())
}
