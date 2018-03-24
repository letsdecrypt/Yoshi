use shellexpand;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use util::{is_valid_file, calc_md5};

pub fn get_boot9() -> Option<String> {
    let paths = [
        "boot9.bin",
        "boot9_prot.bin",
        "~/.3ds/boot9.bin",
        "~/.3ds/boot9_prot.bin",
    ];
    for path in paths.iter() {
        match is_valid_file(path) {
            false => {}
            true => {
                let mut keys_offset = 0;
                let mut key: [u8; 0x10] = [0; 0x10];
                let real_path = shellexpand::tilde(path).into_owned();
                {
                    let mut f = File::open(&real_path).unwrap();
                    if f.metadata().unwrap().len() == 0x10000 {
                        keys_offset += 0x8000;
                    }
                    if f.seek(SeekFrom::Start(0x59D0 + keys_offset)).is_err() {
                        panic!("seek error")
                    }
                    if f.read_exact(&mut key).is_err() {
                        panic!("read error")
                    }
                }
                if calc_md5(&key) == "e35bf88330f4f1b2bb6fd5b870a679ca" {
                    return Some(real_path);
                } else {
                    panic!("... {}: Corrupt file (invalid key).", real_path);
                }
            }
        }
    }
    return None;
}

pub fn get_cert_chain_retail() -> Option<String> {
    let paths = ["cert_chain_retail.bin", "~/.3ds/cert_chain_retail.bin"];
    for path in paths.iter() {
        match is_valid_file(path) {
            false => {}
            true => {
                let real_path = shellexpand::tilde(path).into_owned();
                return Some(real_path);
            }
        }
    }
    return None;
}

pub fn get_ticket_tmd() -> Option<String> {
    let paths = ["ticket_tmd.bin", "~/.3ds/ticket_tmd.bin"];

    for path in paths.iter() {
        match is_valid_file(path) {
            false => {}
            true => {
                let real_path = shellexpand::tilde(path).into_owned();
                return Some(real_path);
            }
        }
    }
    return None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_boot9() {
        assert!(get_boot9().is_some());
    }

    #[test]
    fn check_cert() {
        assert!(get_cert_chain_retail().is_some());
    }

    #[test]
    fn check_ticket() {
        assert!(get_ticket_tmd().is_some())
    }
}
