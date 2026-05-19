// Original comment by Silent:
// UG's binary was not compiled with the Watcom compiler, but it seems to use very aggressive optimizations.
// To make our life easier, reuse prologues/epilogues similar to what Watcom needs.
// Some of those register might not -need- to be saved, but it's better to save too much than too little.

#[macro_export]
// Those macros written by an LLM, I am not familiar with Rust macros yet.
macro_rules! NAKED_FUNC_PROLOG {
    ($local_size:expr) => {
        concat!(
            "push ebp\n",
            "mov ebp, esp\n",
            "sub esp, ", $local_size, "\n",
            "push ebx\n",
            "push ecx\n",
            "push edx\n",
            "push esi\n",
            "push edi\n"
        )
    };
}

#[macro_export]
// Those macros written by an LLM, I am not familiar with Rust macros yet.
macro_rules! NAKED_FUNC_EPILOG {
    () => {
        "pop edi\n\
         pop esi\n\
         pop edx\n\
         pop ecx\n\
         pop ebx\n\
         mov esp, ebp\n\
         pop ebp\n\
         ret\n"
    };
}
