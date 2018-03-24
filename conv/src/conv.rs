extern crate byteorder;
extern crate crypto;
extern crate num_bigint;
extern crate num_traits;
extern crate indicatif;

use self::byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use self::crypto::aes::{ctr, KeySize::KeySize128};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::num_bigint::BigUint;
use self::num_traits::{FromPrimitive, Num, ToPrimitive};
use self::indicatif::ProgressBar;

use conv_lib::get_bins::get_boot9;
use conv_lib::get_bins::get_cert_chain_retail;
use conv_lib::get_bins::get_ticket_tmd;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write, BufReader, BufWriter};
use std::iter::repeat;
use std::path::Path;
use std::mem;

const READ_SIZE: usize = 0x800000;

fn rotate_left_in_128(val: BigUint, r_bits: usize) -> BigUint {
    let max_bits = 128usize;
    let max = BigUint::from_bytes_le(&vec![0xffu8; 0x10]);
    (val.clone() << r_bits % max_bits) & max.clone()
        | ((val.clone() & max.clone()) >> (max_bits - (r_bits % max_bits)))
}

pub fn conv(full_path: &Path, stem: &str, output_path: &str, verbose: bool) {
    let rom_file = File::open(full_path).unwrap();
    let mut rom = BufReader::with_capacity(READ_SIZE * 0x10, rom_file);

    let mut encrypted = false;
    let mut key = BigUint::from_bytes_le(&vec![0u8; 0x10]);

    let mu: BigUint = BigUint::from(0x200u64);
    let game_cxi_offset: BigUint;
    let game_cxi_size: BigUint;
    let manual_cfa_offset: BigUint;
    let manual_cfa_size: BigUint;
    let dlpchild_cfa_offset: BigUint;
    let dlpchild_cfa_size: BigUint;
    let mut tmd_padding = vec![0u8; 0xC];
    let mut tmd_size = 0xB34u32;
    let mut content_index = 0b10000000u8;
    let mut content_count = 1u8;
    let title_id: BigUint;
    let mut save_size = vec![0u8; 0x4];
    let mut ncch_header = vec![0u8; 0x200];
    let mut extheader = vec![0u8; 0x400];
    let mut exefs_icon = vec![0u8; 0x36C0];
    let mut dependency_list = vec![0u8; 0x180];

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
        let mut new_extheader_hash = vec![0u8; 0x20];
        sha.input(&extheader);
        sha.result(&mut new_extheader_hash);
        // get dependency list for meta region
        dependency_list = extheader[0x40..0x1C0].to_vec();
        // get save data size for tmd
        save_size = extheader[0x1C0..0x1C4].to_vec();
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
        if rom.seek(SeekFrom::Start(game_cxi_offset.to_u64().unwrap()))
            .is_err()
            {
                return;
            }
        if rom.read_exact(&mut ncch_header).is_err() {
            return;
        }
        ncch_header.splice(0x160..0x180, new_extheader_hash.iter().cloned());
    }
    // get icon from ExeFS
    {
        println!("Getting SMDH...");
        let exefs_offset = BigUint::from_bytes_le(&ncch_header[0x1A0..0x1A4]) * mu.clone();
        if rom.seek(SeekFrom::Start(
            (game_cxi_offset.clone() + exefs_offset).to_u64().unwrap(),
        )).is_err()
            {
                return;
            }
        let mut exefs_file_header = vec![0u8; 0x40];
        rom.read_exact(&mut exefs_file_header);
        if encrypted {
            println!("Decrypting ExeFS Header...");
            let mut dec_buff = vec![0u8; 0x40];
            let mut exefs_ctr_iv_str = title_id.to_str_radix(0x10);
            let mut ap = "0200000000000000";
            exefs_ctr_iv_str.push_str(ap);
            let exefs_ctr_iv = BigUint::from_str_radix(&exefs_ctr_iv_str, 0x10).unwrap();
            let mut k = key.clone().to_bytes_le();
            if k.len() < 16 {
                let diff = 16 - k.len();
                k.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            k.reverse();
            let mut iv = exefs_ctr_iv.to_bytes_le();
            if iv.len() < 16 {
                let diff = 16 - iv.len();
                iv.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
            }
            iv.reverse();
            let mut dec = ctr(KeySize128, &k, &iv);
            dec.process(&exefs_file_header, &mut dec_buff);
            exefs_file_header = dec_buff.clone();
        }
        // get the ICON
        for i in 0..4 {
            let mark_start = i * 0x10;
            let mark_end = mark_start + 0x8;
            let offset_start = mark_start + 0x8;
            let offset_end = mark_start + 0xc;
            let mut mark = exefs_file_header[mark_start..mark_end].to_vec();
            mark.retain(|&x| x != 0);
            // println!("{}", String::from_utf8(mark.clone()).unwrap());
            if &mark == b"icon" {
                let exefs_icon_offset =
                    BigUint::from_bytes_le(&exefs_file_header[offset_start..offset_end]);
                rom.seek(SeekFrom::Current(
                    exefs_icon_offset.to_i64().unwrap() + 0x200 - 0x40,
                ));
                rom.read_exact(&mut exefs_icon);
                if encrypted {
                    let mut dec_buff = vec![0u8; 0x36C0];
                    let mut exefs_ctr_iv_str = title_id.to_str_radix(0x10);
                    let mut ap = "0200000000000000";
                    exefs_ctr_iv_str.push_str(ap);
                    let exefs_ctr_iv = BigUint::from_str_radix(&exefs_ctr_iv_str, 0x10).unwrap();
                    let exefs_icon_iv =
                        exefs_ctr_iv + (exefs_icon_offset >> 4) + BigUint::from_u32(0x20).unwrap();
                    let mut k = key.clone().to_bytes_le();
                    if k.len() < 16 {
                        let diff = 16 - k.len();
                        k.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
                    }
                    k.reverse();
                    let mut iv = exefs_icon_iv.to_bytes_le();
                    if iv.len() < 16 {
                        let diff = 16 - iv.len();
                        iv.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
                    }
                    iv.reverse();
                    let mut dec = ctr(KeySize128, &k, &iv);
                    dec.process(&exefs_icon, &mut dec_buff);
                    exefs_icon = dec_buff.clone();
                }
                break;
            }
        }
    }
    // tmd padding/size and content count/index
    {
        if manual_cfa_offset.to_u64().unwrap() != 0 {
            tmd_padding.append(&mut repeat(0u8).take(0x10).collect::<Vec<u8>>());
            content_count += 1;
            tmd_size += 0x30;
            content_index += 0b01000000;
        }

        if dlpchild_cfa_offset.to_u64().unwrap() != 0 {
            tmd_padding.append(&mut repeat(0u8).take(0x10).collect::<Vec<u8>>());
            content_count += 1;
            tmd_size += 0x30;
            content_index += 0b00100000;
        }
    }
    // cia writing
    {
        println!("Writing CIA header...");
        let cia_file = File::create(format!("{}/{}.cia", output_path, stem)).unwrap();
        let mut cia = BufWriter::with_capacity(READ_SIZE * 0x10, cia_file);
        let mut chunk_records = vec![];

        chunk_records.write_u32::<BigEndian>(0u32);
        chunk_records.write_u32::<BigEndian>(0);
        chunk_records.write_u32::<BigEndian>(0);
        chunk_records.write_u32::<BigEndian>(game_cxi_size.to_u32().unwrap());

        for i in 0..8 {
            chunk_records.write_u32::<BigEndian>(0);
        }
        if manual_cfa_offset.to_u64().unwrap() != 0 {
            chunk_records.write_u32::<BigEndian>(1u32);
            chunk_records.write_u32::<BigEndian>(0x10000);
            chunk_records.write_u32::<BigEndian>(0);
            chunk_records.write_u32::<BigEndian>(manual_cfa_size.to_u32().unwrap());
            for i in 0..8 {
                chunk_records.write_u32::<BigEndian>(0);
            }
        }
        if dlpchild_cfa_offset.to_u64().unwrap() != 0 {
            chunk_records.write_u32::<BigEndian>(2u32);
            chunk_records.write_u32::<BigEndian>(0x20000);
            chunk_records.write_u32::<BigEndian>(0);
            chunk_records.write_u32::<BigEndian>(dlpchild_cfa_size.to_u32().unwrap());
            for i in 0..8 {
                chunk_records.write_u32::<BigEndian>(0);
            }
        }
        let content_size = game_cxi_size.clone() + manual_cfa_size + dlpchild_cfa_size;

        let mut initial_cia_header = vec![];

        initial_cia_header.write_u32::<LittleEndian>(0x2020);
        initial_cia_header.write_u16::<LittleEndian>(0);
        initial_cia_header.write_u16::<LittleEndian>(0);
        initial_cia_header.write_u32::<LittleEndian>(0xA00);
        initial_cia_header.write_u32::<LittleEndian>(0x350);

        initial_cia_header.write_u32::<LittleEndian>(tmd_size);
        initial_cia_header.write_u32::<LittleEndian>(0x3AC0);
        initial_cia_header.write_u32::<LittleEndian>(content_size.to_u32().unwrap());
        initial_cia_header.write_u32::<LittleEndian>(0);
        initial_cia_header.write_u8(content_index);

        // initial CIA header
        cia.write(&initial_cia_header);
        // padding
        cia.write(&vec![0u8; 0x201F]);
        // cert chain
        cia.write(&cert_buff);
        // ticket, tmd
        cia.write(&ticket_buff);
        // padding
        cia.write(&vec![0u8; 0x96C]);
        // chunk records in tmd
        cia.write(&chunk_records);
        // padding
        cia.write(&tmd_padding);

        // write content count in tmd
        cia.seek(SeekFrom::Start(0x2F9F));
        cia.write(&[content_count]);
        // write title ID in ticket and tmd
        let mut title_id_hex = title_id.to_bytes_le();
        if title_id_hex.len() < 8 {
            let diff = 8 - title_id_hex.len();
            title_id_hex.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
        }
        title_id_hex.reverse();
        cia.seek(SeekFrom::Start(0x2C1C));
        cia.write(&title_id_hex);
        cia.seek(SeekFrom::Start(0x2F4C));
        cia.write(&title_id_hex);

        // write save size in tmd
        cia.seek(SeekFrom::Start(0x2F5A));
        cia.write(&save_size);

        // Game Executable CXI NCCH Header + first-half ExHeader

        {
            cia.seek(SeekFrom::End(0));
            let mut game_cxi_hash = vec![0u8; 0x20];
            let mut sha = Sha256::new();
            sha.input(&ncch_header);
            cia.write(&ncch_header);
            sha.input(&extheader);
            cia.write(&extheader);
            {
                println!("Writing Game Executable CXI...");
                rom.seek(SeekFrom::Start(game_cxi_offset.to_u64().unwrap() + 0x200 + 0x400)); // skip the ncch_header and extheader
                let mut left = game_cxi_size.to_isize().unwrap() - 0x200 - 0x400;
                let bar = ProgressBar::new(left as u64);
                let mut buff = vec![0u8; READ_SIZE];
                while left > 0 {
                    if left < READ_SIZE as isize {
                        buff = vec![0u8; left as usize];
                    }
                    rom.read_exact(&mut buff);
                    cia.write(&buff);
                    sha.input(&buff);
                    left -= READ_SIZE as isize;
                    bar.inc((if left < 0 { (left + READ_SIZE as isize) as usize } else { READ_SIZE }) as u64);
                }
                bar.finish();
            }
            sha.result(&mut game_cxi_hash);
            println!("game_cxi_hash: {:016X}", BigUint::from_bytes_be(&game_cxi_hash));
        }
    }
}
