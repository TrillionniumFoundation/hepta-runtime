fn main() {
 let path=std::env::var("HIA_SSH19_NATIVE_LIB").expect("explicit actual native library directory");
 println!("cargo:rustc-link-search=native={path}");
 println!("cargo:rerun-if-env-changed=HIA_SSH19_NATIVE_LIB");
}
