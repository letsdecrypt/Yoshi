extern crate shellexpand;

use util::{is_valid_file, calc_md5};
use std::path::Path;
use std::fs::{metadata, File};
use std::io::{Read, Seek, SeekFrom};

pub fn get_boot9() -> Option<&'static str> {
    let paths = [
        "boot9.bin",
        "boot9_prot.bin",
        "~/.3ds/boot9.bin",
        "~/.3ds/boot9_prot.bin",
    ];
    for path in paths.iter() {
        match is_valid_file(path) {
            false => println!("... {}: File doesn\'t exist.", path),
            true => {
                let mut keys_offset = 0;
                let mut key: [u8; 0x10] = [0; 0x10];
                let real_path = shellexpand::tilde(path).into_owned();
                let meta = metadata(&real_path).unwrap();
                let b9_path = Path::new(&real_path);
                let mut f = File::open(b9_path).unwrap();
                if meta.len() == 0x10000 {
                    keys_offset += 0x8000;
                }
                if f.seek(SeekFrom::Start(0x59D0 + keys_offset)).is_err() {
                    panic!("seek error")
                }
                if f.read_exact(&mut key).is_err() {
                    panic!("read error")
                }
                if calc_md5(&key) == "e35bf88330f4f1b2bb6fd5b870a679ca" {
                    println!("... {}: Correct key found.", real_path);
                    return Some(path);
                } else {
                    panic!("... {}: Corrupt file (invalid key).", real_path);
                }
            }
        }
    }
    return None;
}

pub fn cert_chain_retail() -> Option<&'static str> {
    let paths = ["cert_chain_retail.bin", "~/.3ds/cert_chain_retail.bin"];
    for path in paths.iter() {
        match is_valid_file(path) {
            false => println!("... {}: File doesn\'t exist.", path),
            true => {
                let real_path = shellexpand::tilde(path).into_owned();
                println!("... {}: Correct cert_chain_retail found.", real_path);
                return Some(path);
            }
        }
    }
    return None;
}

pub fn ticket_tmd() -> Option<&'static str> {
    let paths = ["ticket_tmd.bin", "~/.3ds/ticket_tmd.bin"];

    for path in paths.iter() {
        match is_valid_file(path) {
            false => println!("... {}: File doesn\'t exist.", path),
            true => {
                let real_path = shellexpand::tilde(path).into_owned();
                println!("... {}: Correct ticket_tmd found.", real_path);
                return Some(path);
            }
        }
    }
    return None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot9_found() {
        assert!(get_boot9().is_some())
    }
}
