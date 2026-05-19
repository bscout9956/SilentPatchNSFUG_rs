// Custom typedefs, only those that this project uses
// Reference: https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types

pub type DWORD = u32;
pub type WORD = u16;
pub type LCID = DWORD;
pub type LPCSTR = *const i8;
pub type LPSTR = *mut i8;
