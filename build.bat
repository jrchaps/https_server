@echo off
cls
echo Building...

clang ^
https_server.c -o https_server.exe ^
-I ../jrc_modules ^
-I ../jrc_modules/ecdsa_secp256r1_sha256/tinycrypt/lib/include ^
-march=native ^
-O0 ^
-g -Xlinker /INCREMENTAL:NO ^
-D runtime_checks ^
--config ../jrc_modules/clang_build_flags.cfg