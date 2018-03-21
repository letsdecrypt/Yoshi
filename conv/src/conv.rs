extern crate crypto;
extern crate num_bigint;
extern crate num_traits;

use self::num_traits::FromPrimitive;
use self::num_traits::ToPrimitive;
use self::num_bigint::BigUint;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use conv_lib::get_bins::get_boot9;
use conv_lib::get_bins::get_cert_chain_retail;
use conv_lib::get_bins::get_ticket_tmd;

// media unit
const READ_SIZE: u32 = 0x800000;

fn rotate_left_in_128(val: BigUint, r_bits: usize) -> BigUint {
    let max_bits = 128usize;
    let max = BigUint::from_bytes_le(&vec![0xffu8; 0x10]);
    (val.clone() << r_bits % max_bits) & max.clone() | ((val.clone() & max.clone()) >> (max_bits - (r_bits % max_bits)))
}

pub fn conv(full_path: &Path, stem: &str, output_path: &str, verbose: bool) {
    let mut rom = File::open(full_path).unwrap();
    let mut cia = File::create(format!("{}/{}.cia", output_path, stem)).unwrap();

    let mut encrypted = false;
    let mut key: BigUint;

    let mu: BigUint = BigUint::from(0x200u64);
    let game_cxi_offset: BigUint;
    let game_cxi_size: BigUint;
    let manual_cfa_offset: BigUint;
    let manual_cfa_size: BigUint;
    let dlpchild_cfa_offset: BigUint;
    let dlpchild_cfa_size: BigUint;
    let tmd_padding: [u8; 0xC];
    let tmd_size: BigUint;
    let content_index: u8;
    let content_count: u8;
    let title_id: BigUint;
    let save_size: u32;
    let ncch_header: [u8; 0x200];
    let extheader: [u8; 0x400];
    let exefs_icon: [u8; 0x36C0];
    let dependency_list: [u8; 0x180];

    let mut boot9_key = vec![0u8; 0x10];
    let mut cert_buff = Vec::<u8>::new();
    let mut ticket_buff = Vec::<u8>::new();
    {
        let mut cert_chain_retail = File::open(get_cert_chain_retail().unwrap()).unwrap();
        let mut ticket_tmd = File::open(get_ticket_tmd().unwrap()).unwrap();
        let mut boot9 = File::open(get_boot9().unwrap()).unwrap();

        if let Ok(size) = cert_chain_retail.read_to_end(&mut cert_buff) {
            debug!("cert_chain_retail size: {}", size);
        }
        if let Ok(size) = ticket_tmd.read_to_end(&mut ticket_buff) {
            debug!("ticket_tmd size: {}", size);
        }
        {
            let mut keys_offset = 0;
            if boot9.metadata().unwrap().len() == 0x10000 {
                keys_offset += 0x8000;
            }
            if boot9.seek(SeekFrom::Start(0x59D0 + keys_offset)).is_err() {
                return;
            }
            // care big endian
            if boot9.read_exact(&mut boot9_key).is_err() {
                println!("boot9 read failed");
                return;
            }
        }
    }
    // check for NCSD magic
    {
        if rom.seek(SeekFrom::Start(0x100)).is_err() {
            return;
        }
        let mut buff = vec![0u8; 0x4];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        if &buff != b"NCSD" {
            println!("{} is not a CCI file (missing NCSD magic)", stem);
            return;
        }
        debug!("NCSD check pass");
    }
    {
        if rom.seek(SeekFrom::Start(0x108)).is_err() {
            return;
        }
        let mut buff = vec![0u8; 0x8];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        title_id = BigUint::from_bytes_le(&buff);
        println!("\nTitle ID {:016X}", title_id);
    }
    // get partition sizes
    {
        if rom.seek(SeekFrom::Start(0x120)).is_err() {
            return;
        }
        let mut buff = vec![0u8; 0x4];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        game_cxi_offset = BigUint::from_bytes_le(&buff) * mu.clone();
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        game_cxi_size = BigUint::from_bytes_le(&buff) * mu.clone();
        println!("\nGame Executable CXI Size: {:X}", game_cxi_size);
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        manual_cfa_offset = BigUint::from_bytes_le(&buff) * mu.clone();
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        manual_cfa_size = BigUint::from_bytes_le(&buff) * mu.clone();
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        println!("Manual CFA Size: {:X}", manual_cfa_size);
        dlpchild_cfa_offset = BigUint::from_bytes_le(&buff) * mu.clone();
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        dlpchild_cfa_size = BigUint::from_bytes_le(&buff) * mu.clone();
        println!("Download Play child CFA Size: {:X}\n", dlpchild_cfa_size);
    }
    // check for NCCH magic
    // prevents NAND dumps from being "converted"
    {
        if rom.seek(SeekFrom::Start(
            game_cxi_offset.to_u64().unwrap() + 0x100u64,
        )).is_err()
            {
                return;
            }
        let mut buff = vec![0u8; 0x4];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        if &buff != b"NCCH" {
            println!("{} is not a CCI file (missing NCCH magic)", stem);
            return;
        }
    }
    //  get the encryption type
    {
        if rom.seek(SeekFrom::Start(game_cxi_offset.to_u64().unwrap() + 0x18F))
            .is_err()
            {
                return;
            }
        let mut buff = vec![0u8; 0x1];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        let encryption = buff.first().unwrap();
        encrypted = encryption & 0x4 == 0;
        let zero_key = encryption & 0x1 != 0;
        if encrypted {
            if zero_key {
                key = BigUint::from_bytes_le(&vec![0u8; 0x10]);
            } else {
                if rom.seek(SeekFrom::Start(game_cxi_offset.to_u64().unwrap()))
                    .is_err()
                    {
                        return;
                    }
                let mut buff = vec![0u8; 0x10];
                // care big endian
                if rom.read_exact(&mut buff).is_err() {
                    return;
                }
                let key_y = BigUint::from_bytes_be(&buff);
                println!("key_y: {:016X}", key_y);
                let orig_ncch_key = BigUint::from_bytes_be(&boot9_key);
                println!("orig_ncch_key: {:016X}", orig_ncch_key);
                let addition =
                    BigUint::parse_bytes(b"1FF9E9AAC5FE0408024591DC5D52768A", 16).unwrap();
                println!("addition: {}", addition);
                let p1 = rotate_left_in_128(orig_ncch_key, 2);
                let p2 = p1 ^ key_y;
                let p3 = p2 + addition;
                key = rotate_left_in_128(p3, 87);
                println!("Normal key: {:016X}", key);
            }
        }
    }
    // let's converting
    {
        println!("Converting {} ({})...", stem, if encrypted { "encrypted" } else { "decrypted" });
    }
    // Game Executable fist-half ExtHeader
    {}
}
