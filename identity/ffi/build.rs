use cbindgen::ItemType;
use dart_bindgen::{config::*, Codegen};
use std::env;
fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut config = cbindgen::Config::default();
    config.language = cbindgen::Language::C;
    config.export.item_types = vec![ItemType::Structs, ItemType::Functions];
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("binding.h");
    let config = DynamicLibraryConfig {
        ios: DynamicLibraryCreationMode::Executable.into(),
        android: DynamicLibraryCreationMode::open("libidentity.so").into(),
        ..Default::default()
    };
    let bindings = Codegen::builder()
        .with_src_header("binding.h")
        .with_lib_name("libidentity")
        .with_config(config)
        .with_allo_isolate()
        .build()
        .unwrap()
        .generate()
        .unwrap();
    bindings.write_to_file("ffi.dart").unwrap();
}
