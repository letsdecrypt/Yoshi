#[macro_use]
extern crate clap;
extern crate conv_lib;
extern crate shellexpand;

use clap::{App, AppSettings, Arg};
use conv_lib::conv::conv;
use std::path::Path;

fn main() {
    let app = App::new(crate_name!())
        .author(crate_authors!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::ColorAuto)
        .setting(AppSettings::ArgRequiredElseHelp)
        .args(&[
            Arg::with_name("overwrite")
                .help("Overwrite existing converted files")
                .short("O")
                .long("overwrite"),
            Arg::with_name("verbose")
                .help("Print more information")
                .short("v")
                .long("verbose"),
        ])
        .args(&[
            Arg::with_name("output")
                .help("Save converted files in specified directory")
                .short("o")
                .long("output")
                .takes_value(true),
            Arg::with_name("files")
                .multiple(true)
                .last(true)
                .required(true)
                .takes_value(true),
        ]);
    let m = app.get_matches();
    let is_files_present = m.is_present("files");
    if is_files_present {
        let verbose = m.is_present("verbose");
        let overwrite = m.is_present("overwrite");
        let output = m.value_of("output").unwrap_or("./");
        println!("verbose: {}", verbose);
        println!("overwrite: {}", overwrite);
        println!("output: {}", output);
        let output_path = shellexpand::full(output).unwrap().into_owned();
        {
            let files: Vec<_> = m.values_of("files").unwrap().collect();
            for file in files {
                let real_path = shellexpand::full(file).unwrap().into_owned();
                {
                    println!("Processing {}", real_path);
                    let full_path = Path::new(&real_path);
                    if full_path.is_file() {
                        if let Some(stem) = full_path.file_stem() {
                            conv(full_path, stem.to_str().unwrap(), &output_path, verbose);
                        }
                    } else {
                        println!("{} is not a valid file", file);
                    }
                    continue;
                }
            }
        }
    }
}
