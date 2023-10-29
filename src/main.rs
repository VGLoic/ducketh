use ducketh::{Cli, Parser};

fn main() {
    let cli = Cli::parse();

    cli.run();
}
