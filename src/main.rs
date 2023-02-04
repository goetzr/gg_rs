use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Instruction};

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
    let contents = fs::read(&args.pe_file)?;

    let pe = match goblin::Object::parse(&contents)? {
        goblin::Object::PE(pe) => pe,
        _ => return Err(anyhow::Error::msg("ERROR: not a valid PE file".to_string())),
    };

    // pe.sections
    //     .iter()
    //     .filter(|s| s.characteristics & IMAGE_SCN_CNT_CODE != 0)
    //     .for_each(|s| {
    //         let section_name = unsafe {
    //             let name_bytes: Vec<_> = s.name.iter().copied().collect();
    //             String::from_utf8_unchecked(name_bytes)
    //         };
    //         println!("Section name = {}", section_name);
    //         println!("Code size = {}", s.size_of_raw_data);
    //     });
    // std::process::exit(0);

    let code_section = pe
        .sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_CNT_CODE != 0 && s.size_of_raw_data > 0)
        .next();
    let section = code_section.ok_or(anyhow::Error::msg("no code sections".to_string()))?;
    let section_name = unsafe {
        let name_bytes: Vec<_> = section.name.iter().copied().collect();
        String::from_utf8_unchecked(name_bytes)
    };
    let code_file_offset = section.pointer_to_raw_data as u64;
    let code_size = section.size_of_raw_data as usize;
    println!("Code section: {}", section_name);
    println!("File offset = 0x{:x}", code_file_offset);
    println!("Section size = 0x{:x}", code_size);

    let mut pe_file = OpenOptions::new().read(true).open(&args.pe_file)?;
    println!("File size = 0x{:x}", pe_file.metadata().unwrap().len());
    pe_file.seek(SeekFrom::Start(code_file_offset))?;
    let mut code: Vec<u8> = vec![0; code_size];
    pe_file.read(&mut code)?;
    println!("Code size = {:x}", code.len());

    let main_addr: usize = 0x8f0;
    analyze(main_addr as u64, &code[main_addr..main_addr + 0x62]);
    Ok(())
}

fn analyze(entry: u64, code: &[u8]) {
    let mut decoder = Decoder::with_ip(64, code, entry, DecoderOptions::NONE);

    // Initialize this outside the loop because decode_out() writes to every field
    let mut insn = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut insn);

        println!("{:?}", insn.mnemonic());
    }
}
