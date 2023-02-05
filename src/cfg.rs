use iced_x86::{Decoder, DecoderOptions, Instruction};

pub struct CfgBuilder<'a> {
    decoder: Decoder<'a>,
}

pub struct Cfg;

/*
Cfg is a pointer to the first BB starting at the specified IP.
BB holds a vector of instructions.
A BB holds a vector of pointers to the BB's that reference it.
A BB holds a vector of pointers to the BB's that it references.
 */

impl<'a> CfgBuilder<'a> {
    fn build(code: &'a [u8], bitness: u32, ip: u64) -> Self {
        let decoder = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE);
        CfgBuilder { decoder }
    }

    fn build(ip: u64) -> crate::Result<Cfg> {
        Ok(Cfg)
    }
}