use crate::win_types::{DWORD, LCID, WORD};
use std::ffi::c_str;
use std::slice::from_raw_parts_mut;
use std::{ffi::CStr, os::raw::c_char};
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::Globalization::GetDateFormatA;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::core::{PCSTR, PSTR};

static mut CurrentLanguage: *mut i32 = std::ptr::null_mut();

// Used some LLM assistance.
#[unsafe(no_mangle)]
pub extern "C" fn GetAbbrMonthForLanguage(month: WORD, language: i32) -> *const c_char {
    if (1..12).contains(&language) {
        let months: &[&'static CStr; 12] = match language {
            1 => &[
                c"Jan", c"Fev", c"Mar", c"Avr", c"Mai", c"Jun", c"Jul", c"Aou", c"Sep", c"Oct",
                c"Nov", c"Dec",
            ], // French
            2 => &[
                c"Jan", c"Feb", c"Mrz", c"Apr", c"Mai", c"Jun", c"Jul", c"Aug", c"Sep", c"Okt",
                c"Nov", c"Dez",
            ], // German
            3 => &[
                c"Gen", c"Feb", c"Mar", c"Apr", c"Mag", c"Giu", c"Lug", c"Ago", c"Set", c"Ott",
                c"Nov", c"Dic",
            ], // Italian
            4 => &[
                c"Ene", c"Feb", c"Mar", c"Abr", c"May", c"Jun", c"Jul", c"Ago", c"Sep", c"Oct",
                c"Nov", c"Dic",
            ], // Spanish
            5 => &[
                c"Jan", c"Feb", c"Mrt", c"Apr", c"Mei", c"Jun", c"Jul", c"Aug", c"Sep", c"Okt",
                c"Nov", c"Dec",
            ], // Dutch
            6 => &[
                c"Jan", c"Feb", c"Mar", c"Apr", c"Maj", c"Jun", c"Jul", c"Aug", c"Sep", c"Okt",
                c"Nov", c"Dec",
            ], // Swedish
            _ => &[
                c"Jan", c"Feb", c"Mar", c"Apr", c"May", c"Jun", c"Jul", c"Aug", c"Sep", c"Oct",
                c"Nov", c"Dec",
            ], // English
        };

        return months[(month - 1) as usize].as_ptr();
    }
    // Original comment: Should never happen
    c"???".as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn GetDateFormatA_NullTerminated(
    Locale: LCID,
    dwFlag: DWORD,
    lpDate: *const SYSTEMTIME,
    lpFormat: PCSTR,
    lpDateStr: PSTR,
    cchDate: i32,
) -> i32 {
    let result: i32 =
        unsafe { GetDateFormatA(Locale, dwFlag, lpDate, lpFormat, lpDateStr, cchDate) };

    if !lpDateStr.is_null() && cchDate > 0 {
        unsafe {
            // This line written by an LLM.
            let last_character: *mut u8 = lpDateStr.offset((cchDate - 1) as isize);
            *last_character = 0;
        }
    }

    result
}

// This function heavily assisted by LLM.
#[unsafe(no_mangle)]
pub extern "system" fn GetDateFormatA_GameLanguageFormat(
    Locale: LCID,
    _dwFlags: DWORD,
    lpDate: *const SYSTEMTIME,
    _lpFormat: PCSTR,
    lpDateStr: PSTR,
    cchDate: i32,
) -> i32 {
    unsafe {
        let language: i32 = *CurrentLanguage;

        let mut mutable_lpDate: *const SYSTEMTIME = lpDate;
        let mut local_time: SYSTEMTIME = std::mem::zeroed();

        if lpDate.is_null() {
            GetLocalTime(&mut local_time);
            mutable_lpDate = &local_time as *const SYSTEMTIME;
        }

        match language {
            7 => {
                // Korean
                GetDateFormatA_NullTerminated(
                    Locale,
                    0,
                    mutable_lpDate,
                    c"yyyy'-'MM'-'dd".as_ptr() as *const u8,
                    lpDateStr,
                    cchDate,
                )
            }
            8 => {
                // Chinese
                GetDateFormatA_NullTerminated(
                    Locale,
                    0,
                    mutable_lpDate,
                    c"yyyy'/'M'/'d".as_ptr() as *const u8,
                    lpDateStr,
                    cchDate,
                )
            }
            9 => {
                // Japanese
                GetDateFormatA_NullTerminated(
                    Locale,
                    0,
                    mutable_lpDate,
                    c"yyyy'/'MM'/'dd".as_ptr() as *const u8,
                    lpDateStr,
                    cchDate,
                )
            }
            _ => {
                // All latin languages
                let date_deref: SYSTEMTIME = *mutable_lpDate;
                let month: *const i8 = GetAbbrMonthForLanguage(date_deref.wMonth, language);
                let mut month_str: &str = "";

                if !month.is_null() {
                    month_str = c_str::CStr::from_ptr(month).to_str().unwrap();
                }

                // This portion emulates snprintf_s loosely
                let formatted_str: String =
                    format!("{} {} {}", date_deref.wDay, month_str, date_deref.wYear);
                let str_bytes: &[u8] = formatted_str.as_bytes();

                let max_byte_count: usize = (cchDate as usize - 1).min(str_bytes.len());
                let str_slice: &mut [u8] = from_raw_parts_mut(lpDateStr, cchDate as usize);

                str_slice[max_byte_count] = 0;

                (max_byte_count + 1) as i32
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn GetDateFormatA_Fallback(
    Locale: LCID,
    _dwFlags: DWORD,
    lpDate: *const SYSTEMTIME,
    _lpFormat: PCSTR,
    lpDateStr: PSTR,
    cchDate: i32,
) -> i32 {
    unsafe {
        return GetDateFormatA_NullTerminated(
            Locale,
            0,
            lpDate,
            c"yyyy'.'MM'.'dd".as_ptr() as *const u8,
            lpDateStr,
            cchDate,
        );
    }
}

static mut pGetDateFormatA_SilentPatch: extern "system" fn(LCID, DWORD, *const SYSTEMTIME, PCSTR, PSTR, i32) -> i32 = GetDateFormatA_Fallback;
