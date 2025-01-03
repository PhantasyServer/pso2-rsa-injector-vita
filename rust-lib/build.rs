use std::{env, path::PathBuf};

fn main() {
    let sdk_path = env::var("VITASDK").unwrap() + "/arm-vita-eabi/include/";
    let bindings = bindgen::Builder::default()
        .use_core()
        .header("wrapper.h")
        .derive_default(true)
        .derive_debug(true)
        .clang_arg("-I".to_owned() + &sdk_path)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
