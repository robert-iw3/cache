fn main() -> Result<(), wdk_build::ConfigError> {
    std::env::set_var("CARGO_CFG_TARGET_FEATURE", "crt-static");
    println!("cargo:rustc-link-arg=/DRIVER");
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK"); // Essential for OB callbacks
    wdk_build::configure_wdk_binary_build()?;
    Ok(())
}