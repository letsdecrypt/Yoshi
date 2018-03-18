#![feature(i128_type)]
#![feature(u128_type)]

extern crate shellexpand;

mod util;

use util::{convert, calc_md5};


use std::fs::{metadata, File};
use std::io::{SeekFrom, Seek, Read};
use std::path::Path;

fn main() {
    let path = "~/Documents/3ds-hack/3dsconv/New Super Mario Bros. 2.3ds";
    convert(path)
}

fn md5_main() {
    let mut keys_offset = 0u64;
    let mut key: [u8; 0x10] = [0; 0x10];
    let real_path = shellexpand::tilde_with_context("~/.3ds/boot9.bin", std::env::home_dir).into_owned();
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
    let st = calc_md5(&key);
    println!("hash: {}", st);
}