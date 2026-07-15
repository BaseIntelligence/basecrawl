//! Thin install package so `cargo install basecrawl` yields the CLI binary.

fn main() {
    basecrawl_core::cli::main();
}
