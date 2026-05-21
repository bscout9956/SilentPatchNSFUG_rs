@echo off
echo Building mod...
cargo build --target i686-pc-windows-msvc --profile release

:: Replace 'your_crate_name' with the name in your Cargo.toml
:: Replace the path below with your actual game path
set SOURCE=target\i686-pc-windows-msvc\release\silentpatchnfsug_rs.dll
set DEST="Y:\EA Games\NFS Underground\scripts\silentpatchnfsug_rs.asi"

echo Copying to game directory...
copy /Y "%SOURCE%" %DEST%

echo Done!
pause