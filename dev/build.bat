@echo off
cls
echo Building...

if "%1"=="dev" (
    clang ^
    ../%2.c -o temp/%2.exe ^
    -I ../../jrc_modules/modules_4/ecdsa_secp256r1_sha256/tinycrypt/lib/include ^
    -g -Xlinker /INCREMENTAL:NO ^
    -march=native ^
    -O0 ^
    -D slice_bounds_checking ^
    -Weverything ^
    -Wno-newline-eof ^
    -Wno-unused-variable ^
    -Wno-missing-noreturn ^
    -Wno-unused-macros ^
    -Wno-missing-prototypes ^
    -Wno-disabled-macro-expansion ^
    -Wno-missing-variable-declarations ^
    -Wno-unused-parameter ^
    -Wno-switch ^
    -Wno-bad-function-cast ^
    -Wno-shadow ^
    -Wno-extra-semi ^
    -Wno-extra-semi-stmt ^
    -Wno-conditional-uninitialized ^
    -Wno-bitwise-op-parentheses ^
    -Wno-declaration-after-statement ^
    -Wno-strict-prototypes ^
    -Wno-unsafe-buffer-usage
) 