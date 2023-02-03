use std::path::PathBuf;
use std::fs;
use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the PE file to parse.
    #[arg(verbatim_doc_comment, value_name = "FILE")]
    pe_file: PathBuf,
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("ERROR: {}", e);
        std::process::exit(1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let contents = fs::read(args.pe_file)?;
    let pe = match goblin::Object::parse(&contents)? {
        goblin::Object::PE(pe) => pe,
        _ => return Err(anyhow::Error::msg("ERROR: not a valid PE file".to_string())),
    };
    println!("Code sections:");
    let code_sections: Vec<_> = pe.sections.iter().filter(|s| s.characteristics & IMAGE_SCN_CNT_CODE != 0).collect();
    for code_section in &code_sections {
        let section_name = unsafe {
            let name_bytes: Vec<_> = code_section.name.iter().copied().collect();
            String::from_utf8_unchecked(name_bytes)
        };
        println!("\t{}", section_name);
    }
    Ok(())
}
