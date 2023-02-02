use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the PE file to parse.
    #[arg(verbatim_doc_comment, value_name = "FILE")]
    pe_file: PathBuf
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);
}
