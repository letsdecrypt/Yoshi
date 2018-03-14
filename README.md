# Yoshi
it seems too slow to install CIA to a 2DS/3DS with FBI.
but for now, sighax enable us to get the decryption of title.db the the titles installed, so we can install CIA to TF by simulation of the installation with reverse engineer.

## before start
1. review the ARM assembly learned in collage
2. review the Cryptography learner in collage
3. read the doc on [3dbrew](https://www.3dbrew.org)
4. learn from the 3ds hacking community (like [ihaveamac](https://github.com/ihaveamac/3DS-rom-tools))

## features
1. convert 3ds to cia
2. install cia to SD/TF
    1. locate the EmuNAND, [decrypt](https://github.com/letsdecrypt/fuse-3ds) the title.db
    2. write title info to EmuNAND
    3. write decrypted cia to TF