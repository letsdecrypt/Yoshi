extern crate crypto;
extern crate num_bigint;
extern crate num_traits;

use self::crypto::aes::{ctr, KeySize::KeySize128};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::num_traits::{Num, ToPrimitive};
use self::num_bigint::BigUint;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use conv_lib::get_bins::get_boot9;
use conv_lib::get_bins::get_cert_chain_retail;
use conv_lib::get_bins::get_ticket_tmd;
use std::iter::repeat;

// todo: use buffer reader and writer instead of straight op

// media unit
const READ_SIZE: u32 = 0x800000;

fn rotate_left_in_128(val: BigUint, r_bits: usize) -> BigUint {
    let max_bits = 128usize;
    let max = BigUint::from_bytes_le(&vec![0xffu8; 0x10]);
    (val.clone() << r_bits % max_bits) & max.clone()
        | ((val.clone() & max.clone()) >> (max_bits - (r_bits % max_bits)))
}

pub fn conv(full_path: &Path, stem: &str, output_path: &str, verbose: bool) {
    let mut rom = File::open(full_path).unwrap();
    let mut cia = File::create(format!("{}/{}.cia", output_path, stem)).unwrap();

    let mut encrypted = false;
    let mut key = BigUint::from_bytes_le(&vec![0u8; 0x10]);

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
    let save_size: [u8; 0x4];
    let mut ncch_header = [0u8; 0x200];
    let mut extheader = [0u8; 0x400];
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
            key = if zero_key {
                BigUint::from_bytes_le(&vec![0u8; 0x10])
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
                let p4 = rotate_left_in_128(p3, 87);
                println!("Normal key: {:016X}", p4);
                p4
            }
        }
    }
    // let's converting
    {
        println!(
            "Converting {} ({})...",
            stem,
            if encrypted { "encrypted" } else { "decrypted" }
        );
    }
    // Game Executable fist-half ExtHeader
    {
        println!("\nVerifying ExtHeader...");
        if rom.seek(SeekFrom::Start(game_cxi_offset.to_u64().unwrap() + 0x200))
            .is_err()
            {
                return;
            }

        let mut buff = vec![0u8; 0x400];
        if rom.read_exact(&mut buff).is_err() {
            return;
        }
        if encrypted {
            println!("Decrypting ExtHeader...");
            let mut dec_out_buff = vec![0u8; 0x400];
            let mut extheader_ctr_iv_str = title_id.to_str_radix(0x10);
            let mut ap = "0100000000000000";
            extheader_ctr_iv_str.push_str(ap);
            let extheader_ctr_iv = BigUint::from_str_radix(&extheader_ctr_iv_str, 0x10).unwrap();
            let mut k = key.clone().to_bytes_le();
            if k.len() < 16 {
                let diff = 16 - k.len();
                k.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            k.reverse();
            let mut iv = extheader_ctr_iv.to_bytes_le();
            if iv.len() < 16 {
                let diff = 16 - iv.len();
                iv.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            iv.reverse();
            let mut dec = ctr(KeySize128, &k, &iv);
            dec.process(&buff, &mut dec_out_buff);
            let mut sha = Sha256::new();
            sha.input(&dec_out_buff);
            let mut extheader_hash = vec![0u8; 0x20];
            sha.result(&mut extheader_hash);
            if rom.seek(SeekFrom::Start(0x4160)).is_err() {
                return;
            }
            let mut ncch_extheader_hash = vec![0u8; 0x20];
            if rom.read_exact(&mut ncch_extheader_hash).is_err() {
                return;
            }
            if ncch_extheader_hash != extheader_hash {
                println!("This file may be corrupt (invalid ExtHeader hash).");
                println!(
                    "expect: {:032X}",
                    BigUint::from_bytes_be(&ncch_extheader_hash)
                );
                println!("butget: {:032X}", BigUint::from_bytes_be(&extheader_hash));
                return;
            }
            extheader = dec_out_buff.clone();
        } else {
            extheader = buff.clone();
        }
    }
    // patch ExtHeader to make an SD title
    {
        extheader[0xD] |= 2;
        let mut sha = Sha256::new();
        let new_extheader_hash = vec![0u8; 0x20];
        sha.input(&extheader);
        sha.result(&new_extheader_hash);
        // get dependency list for meta region
        dependency_list = extheader[0x40..0x1C0];
        // get save data size for tmd
        save_size = extheader[0x1C0..0x1C4];
        if encrypted {
            println!("Re-encrypting ExtHeader...");
            let mut enc_out_buff = vec![0u8; 0x400];
            let mut extheader_ctr_iv_str = title_id.to_str_radix(0x10);
            let mut ap = "0100000000000000";
            extheader_ctr_iv_str.push_str(ap);
            let extheader_ctr_iv = BigUint::from_str_radix(&extheader_ctr_iv_str, 0x10).unwrap();
            let mut k = key.clone().to_bytes_le();
            if k.len() < 16 {
                let diff = 16 - k.len();
                k.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            k.reverse();
            let mut iv = extheader_ctr_iv.to_bytes_le();
            if iv.len() < 16 {
                let diff = 16 - iv.len();
                iv.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            iv.reverse();
            let mut dec = ctr(KeySize128, &k, &iv);
            dec.process(&extheader, &mut enc_out_buff);
            extheader = enc_out_buff.clone();
        }
        // Game Executable NCCH Header
        println!("\nReading NCCH Header of Game Executable...");
        if rom.seek(SeekFrom::Start(game_cxi_offset.to_u64())).is_err() {
            return;
        }
        if rom.read_exact(&mut ncch_header).is_err(){
            return;
        }
        ncch_header.splice(0x160..0x180, new_extheader_hash.iter().cloned())
    }
    // get icon from ExeFS
    {
        println!("Getting SMDH...");
        let exefs_offset = BigUint::from_bytes_le(ncch_header[0x1A0..0x1A4]) * mu.clone();
        if rom.seek(SeekFrom::Start((game_cxi_offset.clone() + exefs_offset.clone()).to_u64())).is_err(){
            return;
        }
        let mut exefs_file_header= vec![0u8;0x40];
        rom.read_exact(&mut exefs_file_header);
    }
}
