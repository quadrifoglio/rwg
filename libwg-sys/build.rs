const LIB_PATH: &'static str = "wireguard-tools/contrib/embeddable-wg-library";

fn main() {
    cc::Build::new()
        .file(format!("{}/wireguard.c", LIB_PATH))
        .flag("-Wno-unused-parameter")
        .compile("wireguard");
}
