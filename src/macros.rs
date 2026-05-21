// Original comment by Silent:
// UG's binary was not compiled with the Watcom compiler, but it seems to use very aggressive optimizations.
// To make our life easier, reuse prologues/epilogues similar to what Watcom needs.
// Some of those register might not -need- to be saved, but it's better to save too much than too little.

// Those macros written by an LLM, I am not familiar with Rust macros yet.
#[macro_export]
macro_rules! NAKED_FUNC_PROLOG {
    ($local_size:expr) => {
        concat!(
            "push ebp\n",
            "mov ebp, esp\n",
            "sub esp, ",
            $local_size,
            "\n",
            "push ebx\n",
            "push ecx\n",
            "push edx\n",
            "push esi\n",
            "push edi\n"
        )
    };
}

#[macro_export]
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

#[macro_export]
// Replaces: #define SETVMT(a) *((uintptr_t*)this) = (uintptr_t)a
macro_rules! set_vmt {
    ($this:expr, $vmt:expr) => {
        *($this as *mut *const ()) = $vmt as *const ();
    };
}

#[macro_export]
// Replaces: #define EAXJMP(a) { _asm mov eax, a _asm jmp eax }
macro_rules! eax_jmp {
    ($addr:expr) => {
        core::arch::asm!(
            "mov eax, {0}",
            "jmp eax",
            in(reg) $addr,
            options(noreturn)
        );
    };
}

#[macro_export]
// Replaces: #define VARJMP(a) { _asm jmp a }
macro_rules! var_jmp {
    ($addr:expr) => {
        core::arch::asm!(
            "jmp {0}",
            in(reg) $addr,
            options(noreturn)
        );
    };
}

#[macro_export]
macro_rules! mut_ptr {
    ($ext:expr) => {
        &mut *std::ptr::addr_of_mut!($ext)
    };
}