// Custom typedefs, only those that this project uses
// Reference: https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types

use std::os::raw::c_char;

pub type DWORD = u32;
pub type WORD = u16;
pub type LCID = DWORD;
pub type LPCSTR = *const c_char;
pub type LPSTR = *mut c_char;
