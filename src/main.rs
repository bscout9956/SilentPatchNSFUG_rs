use std::{arch::naked_asm, mem};
#[allow(non_snake_case)]
#[repr(C)]
struct RacingCar {
    // Not using char for field_0 as char in Rust is Unicode (4 bytes)
    pub field_0: [u8; 224],
    pub m_lapScores: [f32; 11],
    pub gap10C: [u8; 52],
}

// Original comment by Silent:
// UG's binary was not compiled with the Watcom compiler, but it seems to use very aggressive optimizations.
// To make our life easier, reuse prologues/epilogues similar to what Watcom needs.
// Some of those register might not -need- to be saved, but it's better to save too much than too little.

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

impl RacingCar {
    // We only define this, this isn't meant to be called. It's a compile time check.
    fn _assert_size() {
        const {assert!(mem::size_of::<RacingCar>() == 0x140, "Wrong size: RacingCar")};
    }

    pub fn GetTotalLapScore(&self) -> f32 {
        let mut total_score = 0.0;

        for lap_score in self.m_lapScores {
            total_score += lap_score;
        }

        total_score
    }



}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "cdecl" fn GetTotalLapScore_Hook() -> f32 {
    naked_asm!(
        NAKED_FUNC_PROLOG!("8"),

        "mov [ebp - 4], eax",
        "mov ecx, [ebp - 4]",
        "call {get_score_fn}",

        NAKED_FUNC_EPILOG!(),

        get_score_fn = sym RacingCar::GetTotalLapScore,
    )
}

fn main() {
    println!("Hello, world!");
}
