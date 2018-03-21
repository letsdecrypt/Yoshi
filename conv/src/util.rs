extern crate crypto;
extern crate shellexpand;

use self::crypto::md5::Md5;
use self::crypto::digest::Digest;
use std::mem;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::fs::metadata;

const MU: u32 = 0x200;
// media unit
const READ_SIZE: u32 = 0x800000;
// used from padxorer
const ZERO_KEY: [u8; 0x10] = [0; 0x10];

fn bytes_to_hex_string(bytes: Vec<u8>) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

pub fn is_valid_file(path: &str) -> bool {
    let ref real_path = shellexpand::tilde(path).into_owned();
    Path::new(real_path).is_file()
}

pub fn calc_md5(key: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.input(key);
    hasher.result_str()
}

pub fn convert(path: &str) {
    let ref real_path = shellexpand::tilde(path).into_owned();
    println!("----------\nProcessing {}...", real_path);
    let mut rom = File::open(real_path).unwrap();
    // let (cia_name, _ext) = path.split_at(real_path.len() - 4);
    // let mut temp_str = String::from(cia_name);
    // temp_str.push_str(".cia");
    // let cia_path = Path::new(&temp_str);
    // let cia = File::create(cia_path).unwrap();
    // check for NCSD magic
    // 3DS NAND dumps also have this

    if rom.seek(SeekFrom::Start(0x100)).is_err() {
        panic!("seek NCSD error")
    }
    let mut ncsd_magic: [u8; 0x4] = [0; 0x4];
    if rom.read_exact(&mut ncsd_magic).is_err() {
        panic!("read error")
    }
    if String::from_utf8(ncsd_magic.to_vec()).unwrap() != "NCSD" {
        panic!("\"{}\" is not a CCI file (missing NCSD magic).", real_path);
    }
    // get title ID
    if rom.seek(SeekFrom::Start(0x108)).is_err() {
        panic!("seek title ID error")
    }
    let mut reverse_title_id: [u8; 0x8] = [0; 0x8];
    if rom.read_exact(&mut reverse_title_id).is_err() {
        panic!("read title ID error")
    }
    reverse_title_id.reverse();
    let title_id = reverse_title_id;
    let hex_title_id = bytes_to_hex_string(title_id.to_vec());
    println!("\nTitle ID:{}", hex_title_id);
    // get partition sizes
    if rom.seek(SeekFrom::Start(0x120)).is_err() {
        panic!("seek partition sizes error")
    }
    // find Game Executable CXI
    let mut game_cxi: [u8; 0x8] = [0; 0x8];
    if rom.read_exact(&mut game_cxi).is_err() {
        panic!("read Game Executable CXI error")
    }
    let mut t1 = [0u8; 0x4];
    t1.copy_from_slice(&game_cxi[0..4]);
    let mut t2 = [0u8; 0x4];
    t2.copy_from_slice(&game_cxi[4..8]);
    let game_cxi_offset: u32;
    let game_cxi_size: u32;
    unsafe {
        game_cxi_offset = mem::transmute::<[u8; 4], u32>(t1) * MU;
        game_cxi_size = mem::transmute::<[u8; 4], u32>(t2) * MU;
    }
    println!("\nGame Executable CXI Size: {:X}", game_cxi_size);

    debug_assert_eq!(game_cxi_offset, 0x4000);
    debug_assert_eq!(game_cxi_size, 0x154bc000);

    // find Manual CFA
    let mut manual_cfa: [u8; 0x8] = [0; 0x8];
    if rom.read_exact(&mut manual_cfa).is_err() {
        panic!("read Manual CFA error")
    }
    let mut t1 = [0u8; 0x4];
    t1.copy_from_slice(&manual_cfa[0..4]);
    let mut t2 = [0u8; 0x4];
    t2.copy_from_slice(&manual_cfa[4..8]);
    let manual_cfa_offset: u32;
    let manual_cfa_size: u32;
    unsafe {
        manual_cfa_offset = mem::transmute::<[u8; 4], u32>(t1) * MU;
        manual_cfa_size = mem::transmute::<[u8; 4], u32>(t2) * MU;
    }
    println!("Manual CFA Size: {:X}", manual_cfa_size);
    debug_assert_eq!(manual_cfa_offset, 0x154c0000);
    debug_assert_eq!(manual_cfa_size, 0xdb000);
    // find Download Play child CFA
    let mut dlpchild_cfa: [u8; 0x8] = [0; 0x8];
    if rom.read_exact(&mut dlpchild_cfa).is_err() {
        panic!("read Download Play child CFA error")
    }
    let mut t1 = [0u8; 0x4];
    t1.copy_from_slice(&dlpchild_cfa[0..4]);
    let mut t2 = [0u8; 0x4];
    t2.copy_from_slice(&dlpchild_cfa[4..8]);
    let dlpchild_cfa_offset: u32;
    let dlpchild_cfa_size: u32;
    unsafe {
        dlpchild_cfa_offset = mem::transmute::<[u8; 4], u32>(t1) * MU;
        dlpchild_cfa_size = mem::transmute::<[u8; 4], u32>(t2) * MU;
    }
    println!("Download Play child CFA Size: {:X}", dlpchild_cfa_size);
    debug_assert_eq!(dlpchild_cfa_offset, 0x0);
    debug_assert_eq!(dlpchild_cfa_size, 0x0);
    // check for NCCH magic
    // prevents NAND dumps from being "converted"
    if rom.seek(SeekFrom::Start((game_cxi_offset + 0x100) as u64))
        .is_err()
    {
        panic!("seek NCCH magic error")
    }
    let mut ncsd_magic: [u8; 0x4] = [0; 0x4];
    if rom.read_exact(&mut ncsd_magic).is_err() {
        panic!("read NCCH magic")
    }
    if String::from_utf8(ncsd_magic.to_vec()).unwrap() != "NCCH" {
        panic!("\"{}\" is not a CCI file (missing NCCH magic).", real_path);
    }
    // get the encryption type
    if rom.seek(SeekFrom::Start((game_cxi_offset + 0x18F) as u64))
        .is_err()
    {
        panic!("seek encryption type error")
    }
    let mut encryption_buf: [u8; 0x1] = [0u8; 0x1];
    if rom.read_exact(&mut encryption_buf).is_err() {
        panic!("read encryption type error")
    }
    let encryption_bitmask = encryption_buf.first().unwrap();
    let encrypted = !encryption_bitmask & 0x4;
    let zerokey_encrypted = encryption_bitmask & 0x1;
    let mut key: [u8; 0x10] = [0; 0x10];
    let ctr_extheader_v = hex_title_id.clone().push_str("0100000000000000");
    let ctr_exefs_v = hex_title_id.clone().push_str("0200000000000000");
    if zerokey_encrypted != 0 {
        key = ZERO_KEY;
    } else {
        let mut keys_offset = 0u64;
        let real_path = shellexpand::tilde("~/.3ds/boot9.bin").into_owned();
        let meta = metadata(&real_path).unwrap();
        let b9_path = Path::new(&real_path);
        let mut boot9 = File::open(b9_path).unwrap();
        if meta.len() == 0x10000 {
            keys_offset += 0x8000;
        }
        if boot9.seek(SeekFrom::Start(0x59D0 + keys_offset)).is_err() {
            panic!("seek error")
        }
        if boot9.read(&mut key).is_err() {
            panic!("read error")
        }
    }
    /// here rol fn is need
    /// as rust provide rotate_left
    /// logic:
    /// read 0x10 bytes from rom at game_cxi_offset as key_y u128
    /// read 0x10 bytes from boot9 at keys_offset as key_x u128
    /// 1. key_x rotate left 2, as p1
    /// 2. p1 ^ key_y, as p2
    /// 3. p2 + 0x1FF9E9AAC5FE0408024591DC5D52768A, as p3
    /// 4. p3 rotate left 87, as final key
    println!("{}", bytes_to_hex_string(key.to_vec()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{metadata, File};
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn check_is_file() {
        assert_eq!(is_valid_file("boot9.bin"), true);
    }

    #[test]
    fn check_md5() {
        let mut keys_offset = 0;
        let mut key: [u8; 0x10] = [0; 0x10];
        let real_path = shellexpand::tilde("boot9.bin").into_owned();
        let meta = metadata(&real_path).unwrap();
        let b9_path = Path::new(&real_path);
        let mut f = File::open(b9_path).unwrap();
        if meta.len() == 0x10000 {
            keys_offset += 0x8000;
        }
        if f.seek(SeekFrom::Start(0x59D0 + keys_offset)).is_err() {
            panic!("seek error")
        }
        if f.read(&mut key).is_err() {
            panic!("read error")
        }
        assert_eq!(calc_md5(&key), "e35bf88330f4f1b2bb6fd5b870a679ca")
    }

    #[test]
    fn check_key_calc() {
        /// logic:
        /// read 0x10 bytes from rom at game_cxi_offset as key_y u128
        /// read 0x10 bytes from boot9 at keys_offset as key_x u128
        /// 1. key_x rotate left 2, as p1
        /// 2. p1 ^ key_y, as p2
        /// 3. p2 + 0x1FF9E9AAC5FE0408024591DC5D52768A, as p3
        /// 4. p3 rotate left 87, as final key
        let key_x = 0xB98E95CECA3E4D171F76A94DE934C053u128;
        let key_y = 0x6D6FAEFB2391CF40A87A46DAE4BD438Fu128;
        let p1 = key_x.rotate_left(2);
        let p2 = p1 ^ key_y;
        let p3 = p2 + 0x1FF9E9AAC5FE0408024591DC5D52768Au128;
        let key = p3.rotate_left(87);
        assert_eq!(key, 0xE4CEE05CA5D5A7F1B568B37F926BF33Au128);
    }
}
