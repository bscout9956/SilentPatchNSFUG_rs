# SilentPatch for Need for Speed: Underground - Rust Fork 

This repository is a fork of Silent's SilentPatch for Need for Speed: Underground written in Rust.
This was done as a PoC and a test to see how far I could go porting something from another "systems" language into Rust.

Initially I planned to do this project as much by hand as I possibly could. 
However, as I further developed it I encountered concepts of "low level" programming, compilers and microarchitecture that I wasn't very familiar with (or knew a surface level amount of).
(e.g: ABI, call  conventions, externs, cdecl/declspec vs thiscall etc etc.)
Learning those the proper way would be a huge roadblock, so I decided to at least ask an LLM when hitting them. The point of this was to push myself with Rust and hopefully learn a thing or two while doing something fun.

Unfortunately the lack of knowledge piled up fast and I ended up using LLMs 50% of the time. 
I tried my best not to copy and paste the code and actually read it, try to understand it and then write it myself (character by character).

# Bugs
There are probably dozens of bugs in the code, partially due to LLM usage and partially due to my own stupidity. 
This project is extremely unfinished and the code is not very idiomatic as I mostly "translated" the original logic into something compilable and ever so slightly usable.

# Important
Please see ETHICS.md for a bit more information on LLM/AI usage in this project.
The ported libraries may not work completely and there's only support for 32bit DLL Injection as I haven't yet ported the necessary Trampoline code required by the Hooking code.
Rust does not support preprocessor definitions like C/C++ so I had to do some stinky workarounds to make it all fit together. See Cargo.toml and build.rs to have an idea of what's up there lol.
