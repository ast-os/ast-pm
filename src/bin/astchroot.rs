fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(ast::cli::run_tool("astchroot", a));
}
