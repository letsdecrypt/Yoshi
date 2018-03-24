use crypto::digest::Digest;
use crypto::md5::Md5;
use shellexpand;
use std::path::Path;

pub fn is_valid_file(path: &str) -> bool {
    let ref real_path = shellexpand::tilde(path).into_owned();
    Path::new(real_path).is_file()
}

pub fn calc_md5(key: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.input(key);
    hasher.result_str()
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
}
