use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, MasmFormatter};

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

    let code_section = pe
        .sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_CNT_CODE != 0)
        .next();
    let section = code_section.ok_or(anyhow::Error::msg("no code sections".to_string()))?;
    let section_name = unsafe {
        let name_bytes: Vec<_> = section.name.iter().copied().collect();
        String::from_utf8_unchecked(name_bytes)
    };
    println!("Code section: {}", section_name);

    let mut pe_file = OpenOptions::new().read(true).open(&args.pe_file)?;
    pe_file.seek(SeekFrom::Start(section.pointer_to_raw_data as u64))?;
    let mut code: Vec<_> = Vec::new();
    code.reserve_exact(section.size_of_raw_data as usize);
    pe_file.read(code.as_mut_slice())?;

    print_start_of_code(TODO entry, &code[0..16]);
    Ok(())
}

fn print_start_of_code(entry: u64, code: &[u8]) {
    const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

    let mut decoder =
        Decoder::with_ip(32, code, entry, DecoderOptions::NONE);

    let mut formatter = MasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_first_operand_char_index(10);

    // String implements FormatterOutput
    let mut output = String::new();

    // Initialize this outside the loop because decode_out() writes to every field
    let mut instruction = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        // Format the instruction ("disassemble" it)
        output.clear();
        formatter.format(&instruction, &mut output);

        // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - entry) as usize;
        let instr_bytes = &code[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}
