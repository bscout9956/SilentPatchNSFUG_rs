// Custom typedefs, only those that this project uses
// Reference: https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types

use std::ffi::c_void;

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

pub type ULONG_PTR = u64;
pub type DWORD_PTR = ULONG_PTR;
pub type DWORD = u32;
pub type WORD = u16;
pub type LCID = DWORD;
pub type LPVOID = *const c_void;
pub type SIZE_T = usize;
pub type LPCVOID = *const c_void;

// 32 bits specific
#[cfg(target_arch = "x86")]
pub type IMAGE_NT_HEADER = IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86")]
pub type IMAGE_THUNK_DATA = IMAGE_THUNK_DATA32;

// 64 bits specific
#[cfg(target_arch = "x86_64")]
pub type IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64;
#[cfg(target_arch = "x86_64")]
pub type IMAGE_NT_HEADER = IMAGE_NT_HEADERS64;
