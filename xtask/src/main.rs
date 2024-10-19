mod run;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Run(run::Options),
}

fn main() -> Result<()> {
    let Options { command } = Parser::parse();

    match command {
        Command::Run(opts) => run::run(opts),
    }
}
