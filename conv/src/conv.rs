use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use crypto::aes::{ctr, KeySize};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use indicatif::ProgressBar;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num, ToPrimitive};

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::iter::repeat;
use std::path::Path;

const READ_SIZE: usize = 0x800000;

fn rotate_left_in_128(val: BigUint, r_bits: usize) -> BigUint {
    let max_bits = 128usize;
    let max = BigUint::from_bytes_le(&vec![0xffu8; 0x10]);
    (val.clone() << r_bits % max_bits) & max.clone()
        | ((val.clone() & max.clone()) >> (max_bits - (r_bits % max_bits)))
}

pub fn conv(
    full_path: &Path,
    stem: &str,
    output_path: &str,
    boot9_key: &[u8],
    cert_chain: &[u8],
    ticket_tmd: &[u8],
    _verbose: bool,
) {
    let rom_file = File::open(full_path).unwrap();
    let mut rom = BufReader::with_capacity(READ_SIZE * 0x10, rom_file);

    let encrypted: bool;
    let mut key = BigUint::from_bytes_le(&vec![0u8; 0x10]);

    let mu = 0x200u32;
    let game_cxi_offset: u32;
    let game_cxi_size: u32;
    let manual_cfa_offset: u32;
    let manual_cfa_size: u32;
    let dlpchild_cfa_offset: u32;
    let dlpchild_cfa_size: u32;
    let mut tmd_padding = vec![0u8; 0xC];
    let mut tmd_size = 0xB34u32;
    let mut content_index = 0b10000000u8;
    let mut content_count = 1u8;
    let title_id: BigUint;
    let save_size: Vec<u8>;
    let mut ncch_header = vec![0u8; 0x200];
    let mut extheader: Vec<u8>;
    let mut exefs_icon = vec![0u8; 0x36C0];
    let dependency_list: Vec<u8>;

    // check for NCSD magic
    {
        rom.seek(SeekFrom::Start(0x100))
            .expect("failed to seek for NCSD in rom");
        let mut buff = vec![0u8; 0x4];
        rom.read_exact(&mut buff)
            .expect("failed to read NCSD in rom");
        if &buff != b"NCSD" {
            println!("{} is not a CCI file (missing NCSD magic)", stem);
            return;
        }
    }
    {
        rom.seek(SeekFrom::Start(0x108))
            .expect("failed to seek for title_id in rom");
        let mut buff = vec![0u8; 0x8];
        rom.read_exact(&mut buff)
            .expect("failed to read title_id in rom");
        title_id = BigUint::from_bytes_le(&buff);
        println!("\nTitle ID {:016X}", title_id);
    }
    // get partition sizes
    {
        rom.seek(SeekFrom::Start(0x120))
            .expect("failed to seek for partition sizes in rom");
        let mut buff = vec![0u8; 0x4];
        rom.read_exact(&mut buff)
            .expect("failed to read game_cxi_offset in rom");
        {
            game_cxi_offset = LittleEndian::read_u32(&buff) * mu;
        }
        rom.read_exact(&mut buff)
            .expect("failed to read game_cxi_size in rom");
        {
            game_cxi_size = LittleEndian::read_u32(&buff) * mu;
        }
        println!("\nGame Executable CXI Size: {:X}", game_cxi_size);
        rom.read_exact(&mut buff)
            .expect("failed to read manual_cfa_offset in rom");
        {
            manual_cfa_offset = LittleEndian::read_u32(&buff) * mu;
        }
        rom.read_exact(&mut buff)
            .expect("failed to read manual_cfa_size in rom");
        {
            manual_cfa_size = LittleEndian::read_u32(&buff) * mu;
        }
        println!("Manual CFA Size: {:X}", manual_cfa_size);
        rom.read_exact(&mut buff)
            .expect("failed to read dlpchild_cfa_offset in rom");
        {
            dlpchild_cfa_offset = LittleEndian::read_u32(&buff) * mu;
        }
        rom.read_exact(&mut buff)
            .expect("failed to read dlpchild_cfa_size in rom");
        {
            dlpchild_cfa_size = LittleEndian::read_u32(&buff) * mu;
        }
        println!("Download Play child CFA Size: {:X}\n", dlpchild_cfa_size);
    }
    // check for NCCH magic
    // prevents NAND dumps from being "converted"
    {
        rom.seek(SeekFrom::Start((game_cxi_offset + 0x100).into()))
            .expect("failed to seek for NCCH in rom");
        let mut buff = vec![0u8; 0x4];
        rom.read_exact(&mut buff)
            .expect("failed to read NCCH in rom");
        if &buff != b"NCCH" {
            println!("{} is not a CCI file (missing NCCH magic)", stem);
            return;
        }
    }
    //  get the encryption type
    {
        rom.seek(SeekFrom::Start((game_cxi_offset + 0x18F).into()))
            .expect("failed to seek for encryption in rom");
        let mut buff = vec![0u8; 0x1];
        rom.read_exact(&mut buff)
            .expect("failed to read encryption in rom");
        let encryption = buff.first().unwrap();
        encrypted = encryption & 0x4 == 0;
        let zero_key = encryption & 0x1 != 0;
        if encrypted {
            key = if zero_key {
                BigUint::from_bytes_le(&vec![0u8; 0x10])
            } else {
                rom.seek(SeekFrom::Start(game_cxi_offset.into()))
                    .expect("failed to seek for key_y in rom");
                let mut buff = vec![0u8; 0x10];
                // big endian
                rom.read_exact(&mut buff)
                    .expect("failed to read key_y in rom");
                let key_y = BigUint::from_bytes_be(&buff);
                // println!("key_y: {:016X}", key_y);
                let orig_ncch_key = BigUint::from_bytes_be(&boot9_key);
                // println!("orig_ncch_key: {:016X}", orig_ncch_key);
                let addition =
                    BigUint::parse_bytes(b"1FF9E9AAC5FE0408024591DC5D52768A", 16).unwrap();
                // println!("addition: {}", addition);
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
        rom.seek(SeekFrom::Start((game_cxi_offset + 0x200).into()))
            .expect("failed to seek for ExtHeader in rom");
        let mut buff = vec![0u8; 0x400];
        rom.read_exact(&mut buff)
            .expect("failed to read ExtHeader in rom");
        if encrypted {
            println!("Decrypting ExtHeader...");
            let mut dec_out_buff = vec![0u8; 0x400];
            let mut extheader_ctr_iv_str = title_id.to_str_radix(0x10);
            let ap = "0100000000000000";
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
            let mut dec = ctr(KeySize::KeySize128, &k, &iv);
            dec.process(&buff, &mut dec_out_buff);
            let mut sha = Sha256::new();
            sha.input(&dec_out_buff);
            let mut extheader_hash = vec![0u8; 0x20];
            sha.result(&mut extheader_hash);
            rom.seek(SeekFrom::Start(0x4160))
                .expect("failed to seek for ncch_extheader_hash in rom");
            let mut ncch_extheader_hash = vec![0u8; 0x20];
            rom.read_exact(&mut ncch_extheader_hash)
                .expect("failed to read ncch_extheader_hash in rom");
            if ncch_extheader_hash != extheader_hash {
                println!("This file may be corrupt (invalid ExtHeader hash).");
                println!(
                    "expect: {:032X}",
                    BigUint::from_bytes_be(&ncch_extheader_hash)
                );
                println!("but get: {:032X}", BigUint::from_bytes_be(&extheader_hash));
                return;
            }
            extheader = dec_out_buff.clone();
        } else {
            extheader = buff.clone();
        }
    }
    // patch ExtHeader to make an SD title
    {
        println!("Patching ExtHeader...");
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
            let ap = "0100000000000000";
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
            let mut dec = ctr(KeySize::KeySize128, &k, &iv);
            dec.process(&extheader, &mut enc_out_buff);
            extheader = enc_out_buff.clone();
        }
        // Game Executable NCCH Header
        println!("\nReading NCCH Header of Game Executable...");
        rom.seek(SeekFrom::Start(game_cxi_offset.into()))
            .expect("failed to seek for NCCH Header of Game Executable in rom");
        rom.read_exact(&mut ncch_header)
            .expect("failed to read NCCH Header of Game Executable in rom");
        ncch_header.splice(0x160..0x180, new_extheader_hash.iter().cloned());
    }
    // get icon from ExeFS
    {
        println!("Getting SMDH...");
        let exefs_offset = LittleEndian::read_u32(&ncch_header[0x1A0..0x1A4]) * mu;
        rom.seek(SeekFrom::Start((game_cxi_offset + exefs_offset).into()))
            .expect("failed to seek for SMDH in rom");
        let mut exefs_file_header = vec![0u8; 0x40];
        rom.read_exact(&mut exefs_file_header)
            .expect("failed to read SMDH in rom");
        if encrypted {
            println!("Decrypting ExeFS Header...");
            let mut dec_buff = vec![0u8; 0x40];
            let mut exefs_ctr_iv_str = title_id.to_str_radix(0x10);
            let ap = "0200000000000000";
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
            let mut dec = ctr(KeySize::KeySize128, &k, &iv);
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
                    LittleEndian::read_u32(&exefs_file_header[offset_start..offset_end]);
                rom.seek(SeekFrom::Current(
                    exefs_icon_offset.to_i64().unwrap() + 0x200 - 0x40,
                )).expect("failed to seek for icon");
                rom.read_exact(&mut exefs_icon)
                    .expect("failed to read icon");
                if encrypted {
                    let mut dec_buff = vec![0u8; 0x36C0];
                    let mut exefs_ctr_iv_str = title_id.to_str_radix(0x10);
                    let ap = "0200000000000000";
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
                    let mut dec = ctr(KeySize::KeySize128, &k, &iv);
                    dec.process(&exefs_icon, &mut dec_buff);
                    exefs_icon = dec_buff.clone();
                }
                break;
            }
        }
    }
    // tmd padding/size and content count/index
    {
        if manual_cfa_offset != 0 {
            tmd_padding.append(&mut repeat(0u8).take(0x10).collect::<Vec<u8>>());
            content_count += 1;
            tmd_size += 0x30;
            content_index += 0b01000000;
        }

        if dlpchild_cfa_offset != 0 {
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

        chunk_records
            .write_u32::<BigEndian>(0u32)
            .expect("failed to write chunk records");
        chunk_records
            .write_u32::<BigEndian>(0)
            .expect("failed to write chunk records");
        chunk_records
            .write_u32::<BigEndian>(0)
            .expect("failed to write chunk records");
        chunk_records
            .write_u32::<BigEndian>(game_cxi_size)
            .expect("failed to write chunk records");

        for _ in 0..8 {
            chunk_records
                .write_u32::<BigEndian>(0)
                .expect("failed to write chunk records");
        }
        if manual_cfa_offset != 0 {
            chunk_records
                .write_u32::<BigEndian>(1u32)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(0x10000)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(0)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(manual_cfa_size)
                .expect("failed to write chunk records");
            for _ in 0..8 {
                chunk_records
                    .write_u32::<BigEndian>(0)
                    .expect("failed to write chunk records");
            }
        }
        if dlpchild_cfa_offset != 0 {
            chunk_records
                .write_u32::<BigEndian>(2u32)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(0x20000)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(0)
                .expect("failed to write chunk records");
            chunk_records
                .write_u32::<BigEndian>(dlpchild_cfa_size)
                .expect("failed to write chunk records");
            for _ in 0..8 {
                chunk_records
                    .write_u32::<BigEndian>(0)
                    .expect("failed to write chunk records");
            }
        }
        let content_size = game_cxi_size + manual_cfa_size + dlpchild_cfa_size;

        let mut initial_cia_header = vec![];

        initial_cia_header
            .write_u32::<LittleEndian>(0x2020)
            .expect("failed to write initial cia head");
        initial_cia_header
            .write_u16::<LittleEndian>(0)
            .expect("failed to write initial cia head");
        initial_cia_header
            .write_u16::<LittleEndian>(0)
            .expect("failed to write initial cia head");
        initial_cia_header
            .write_u32::<LittleEndian>(0xA00)
            .expect("failed to write initial cia head");
        initial_cia_header
            .write_u32::<LittleEndian>(0x350)
            .expect("failed to write initial cia head");

        initial_cia_header
            .write_u32::<LittleEndian>(tmd_size)
            .expect("failed to write cia header");
        initial_cia_header
            .write_u32::<LittleEndian>(0x3AC0)
            .expect("failed to write cia header");
        initial_cia_header
            .write_u32::<LittleEndian>(content_size.to_u32().unwrap())
            .expect("failed to write cia header");
        initial_cia_header
            .write_u32::<LittleEndian>(0)
            .expect("failed to write cia header");
        initial_cia_header
            .write_u8(content_index)
            .expect("failed to write cia header");

        // initial CIA header
        cia.write(&initial_cia_header)
            .expect("cia seek write failed");
        // padding
        cia.write(&vec![0u8; 0x201F])
            .expect("cia seek write failed");
        // cert chain
        cia.write(&cert_chain).expect("cia seek write failed");
        // ticket, tmd
        cia.write(&ticket_tmd).expect("cia seek write failed");
        // padding
        cia.write(&vec![0u8; 0x96C]).expect("cia seek write failed");
        // chunk records in tmd
        cia.write(&chunk_records).expect("cia seek write failed");
        // padding
        cia.write(&tmd_padding).expect("cia seek write failed");
        // write content count in tmd
        cia.seek(SeekFrom::Start(0x2F9F)).expect("cia seek failed");
        cia.write(&[content_count]).expect("cia seek write failed");
        // write title ID in ticket and tmd
        let mut title_id_hex = title_id.to_bytes_le();
        if title_id_hex.len() < 8 {
            let diff = 8 - title_id_hex.len();
            title_id_hex.append(&mut repeat(0u8).take(diff).collect::<Vec<u8>>());
        }
        title_id_hex.reverse();
        cia.seek(SeekFrom::Start(0x2C1C)).expect("cia seek failed");
        cia.write(&title_id_hex).expect("cia seek write failed");
        cia.seek(SeekFrom::Start(0x2F4C)).expect("cia seek failed");
        cia.write(&title_id_hex).expect("cia seek write failed");
        // write save size in tmd
        cia.seek(SeekFrom::Start(0x2F5A)).expect("cia seek failed");
        cia.write(&save_size).expect("cia seek write failed");
        // Game Executable CXI NCCH Header + first-half ExHeader
        {
            cia.seek(SeekFrom::End(0)).expect("cia seek failed");
            let mut game_cxi_hash = vec![0u8; 0x20];
            let mut sha = Sha256::new();
            sha.input(&ncch_header);
            cia.write(&ncch_header).expect("cia seek write failed");
            sha.input(&extheader);
            cia.write(&extheader).expect("cia seek write failed");
            {
                println!("Writing Game Executable CXI...");
                rom.seek(SeekFrom::Start((game_cxi_offset + 0x200 + 0x400).into()))
                    .expect("failed to seek for CXI"); // skip the ncch_header and extheader
                let mut left = (game_cxi_size - 0x200 - 0x400) as usize;
                let mut buff = vec![0u8; READ_SIZE];
                let bar = ProgressBar::new(left as u64);
                while left > 0 {
                    if left < READ_SIZE {
                        buff = vec![0u8; left];
                    }
                    rom.read_exact(&mut buff).expect("failed to read CXI");
                    cia.write(&buff).expect("cia seek write failed");
                    bar.inc(buff.len() as u64);
                    sha.input(&buff);
                    left -= buff.len();
                }
                bar.finish_and_clear();
            }
            sha.result(&mut game_cxi_hash);
            println!(
                "Game Executable CXI SHA-256 hash: {:016X}",
                BigUint::from_bytes_be(&game_cxi_hash)
            );
            cia.seek(SeekFrom::Start(0x38D4)).expect("cia seek failed");
            cia.write(&game_cxi_hash).expect("cia seek write failed");
            chunk_records.splice(0x10..0x30, game_cxi_hash.iter().cloned());
        }
        {
            let mut cr_offset = 0usize;
            //  Manual CFA
            if manual_cfa_offset != 0 {
                cia.seek(SeekFrom::End(0)).expect("cia seek failed");
                let mut hash_buff = vec![0u8; 0x20];
                let mut sha = Sha256::new();
                {
                    println!("Writing Manual CFA...");
                    rom.seek(SeekFrom::Start(manual_cfa_offset.into()))
                        .expect("failed to seek for Manual CFA");
                    let mut left = manual_cfa_size as usize;
                    let mut buff = vec![0u8; READ_SIZE];
                    let bar = ProgressBar::new(left as u64);
                    while left > 0 {
                        if left < READ_SIZE {
                            buff = vec![0u8; left];
                        }
                        rom.read_exact(&mut buff)
                            .expect("failed to read Manual CFA");
                        cia.write(&buff).expect("cia seek write failed");
                        bar.inc(buff.len() as u64);
                        sha.input(&buff);
                        left -= buff.len();
                    }
                    bar.finish_and_clear();
                }
                sha.result(&mut hash_buff);
                println!(
                    "Manual CFA SHA-256 hash: {:016X}",
                    BigUint::from_bytes_be(&hash_buff)
                );
                cia.seek(SeekFrom::Start(0x3904)).expect("cia seek failed");
                cia.write(&hash_buff).expect("cia seek write failed");
                chunk_records.splice(0x40..0x60, hash_buff.iter().cloned());
                cr_offset += 0x30;
            }
            // Download Play child container CFA
            if dlpchild_cfa_offset != 0 {
                cia.seek(SeekFrom::End(0)).expect("cia seek failed");
                let mut hash_buff = vec![0u8; 0x20];
                let mut sha = Sha256::new();
                {
                    println!("Writing Download Play child container CFA...");
                    rom.seek(SeekFrom::Start(dlpchild_cfa_offset.into()))
                        .expect("failed to seek for Download Play");
                    let mut left = manual_cfa_size as usize;
                    let mut buff = vec![0u8; READ_SIZE];
                    let bar = ProgressBar::new(left as u64);
                    while left > 0 {
                        if left < READ_SIZE {
                            buff = vec![0u8; left];
                        }
                        rom.read_exact(&mut buff)
                            .expect("failed to read Download Play");
                        cia.write(&buff).expect("cia seek write failed");
                        bar.inc(buff.len() as u64);
                        sha.input(&buff);
                        left -= buff.len();
                    }
                    bar.finish_and_clear();
                }
                sha.result(&mut hash_buff);
                println!(
                    "Download Play child container CFA SHA-256 hash: {:016X}",
                    BigUint::from_bytes_be(&hash_buff)
                );
                cia.seek(SeekFrom::Start((0x3904 + cr_offset) as u64))
                    .expect("cia seek failed");
                cia.write(&hash_buff).expect("cia seek write failed");
                chunk_records.splice(
                    (0x40 + cr_offset)..(0x60 + cr_offset),
                    hash_buff.iter().cloned(),
                );
            }
        }
        // update final hashes
        {
            println!("\nUpdating hashes...");
            let mut chunk_records_hash = vec![0u8; 0x20];
            let mut sha = Sha256::new();
            sha.input(&chunk_records);
            sha.result(&mut chunk_records_hash);
            println!(
                "Content chunk records SHA-256 hash: {:016X}",
                BigUint::from_bytes_be(&chunk_records_hash)
            );
            cia.seek(SeekFrom::Start(0x2FC7)).expect("cia seek failed");
            cia.write(&[content_count]).expect("cia seek write failed");
            cia.write(&chunk_records_hash)
                .expect("cia seek write failed");
            cia.seek(SeekFrom::Start(0x2FA4)).expect("cia seek failed");
            let mut info_records_hash = vec![0u8; 0x20];
            let mut info_records_sha = Sha256::new();
            info_records_sha.input(&[0, 0, 0, content_count]);
            info_records_sha.input(&chunk_records_hash);
            info_records_sha.input(&vec![0u8; 0x8DC]);
            info_records_sha.result(&mut info_records_hash);
            println!(
                "Content info records SHA-256 hash: {:016X}",
                BigUint::from_bytes_be(&info_records_hash)
            );
            cia.write(&info_records_hash)
                .expect("cia seek write failed");
        }
        // write Meta region
        {
            cia.seek(SeekFrom::End(0)).expect("cia seek failed");
            cia.write(&dependency_list).expect("cia seek write failed");
            cia.write(&vec![0u8; 0x180]).expect("cia seek write failed");
            let mut end_mark = vec![];
            end_mark
                .write_u32::<LittleEndian>(0x2)
                .expect("failed to write end mark");
            cia.write(&end_mark).expect("cia seek write failed");
            cia.write(&vec![0u8; 0xFC]).expect("cia seek write failed");
            cia.write(&exefs_icon).expect("cia seek write failed");
        }
    }
}
