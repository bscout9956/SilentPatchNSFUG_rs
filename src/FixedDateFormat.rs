use std::os::raw::c_char;

use windows_sys::Win32::Foundation::SYSTEMTIME;

use crate::win_types::{DWORD, LCID, LPCSTR, LPSTR, WORD};


static mut CurrentLanguage: *mut i32 = std::ptr::null_mut();

fn GetAbbrMonthForLanguage(month: WORD, language: i32) -> &'static c_char {
    if month >= 1 && month <= 12 {
        match language {
            1 => { // French
                static MONTHS: [&str; 12] = ["Jan", "Fev", "Mar", "Avr", "Mai", "Jun", "Jul", "Aou", "Sep", "Oct", "Nov", "Dec"];
                return MONTHS[(month - 1) as usize];
            },
            2 => { // German
                static MONTHS: [&str; 12] = ["Jan", "Feb", "Mrz", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"];
                return MONTHS[(month - 1) as usize];
            },
            3 => { // Italian
                static MONTHS: [&str; 12] = ["Gen", "Feb", "Mar", "Apr", "Mag", "Giu", "Lug", "Ago", "Set", "Ott", "Nov", "Dic"];
                return MONTHS[(month - 1) as usize];
            },
            4 => { // Spanish
                static MONTHS: [&str; 12] = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
                return MONTHS[(month - 1) as usize];
            },
            5 => { // Dutch
                static MONTHS: [&str; 12] = ["Jan", "Feb", "Mrt", "Apr", "Mei", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dec"];
                return MONTHS[(month - 1) as usize];
            },
            6 => { // Swedish
                static MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "Maj", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dec"];
                return MONTHS[(month - 1) as usize];
            }
            _ => { // English
                static MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                return MONTHS[(month - 1) as usize];
            },
        }
    }
    // Original comment: Should never happen
    "???"
}

fn GetDateFormatA_NullTerminated(Locale: LCID, dwFlag: DWORD, lpDate: *const SYSTEMTIME, lpFormat: LPCSTR, lpDateStr: LPSTR, cchDate: i32) {

}
