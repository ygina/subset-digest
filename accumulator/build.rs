extern crate cc;

fn main() {
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    cc::Build::new()
        .file("src/psum.c")
        .compile("libpsum.a");
    cc::Build::new()
        .file("src/ilp.c")
        .compile("libilp.a");
}
