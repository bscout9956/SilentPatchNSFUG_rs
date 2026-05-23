// TODO: 64 BIT REQUIRES TRAMPOLINE WHICH WILL BE PORTED AT A LATER DATE
// I AM FOCUSING ON THE 32 BIT IMPLEMENTATION AS IT DOESN'T REQUIRE PORTING MORE CODE THAN NECESSARY FOR NFSUGSP
use crate::MemoryMgr::Memory;
use crate::MemoryMgr::Memory::HookType;
use crate::win_types::{DWORD, DWORD_PTR, IMAGE_NT_HEADER, IMAGE_THUNK_DATA, LONG};
use Memory::VP;
use std::cmp::Ordering;
use std::ffi::{CStr, c_char, c_void};
use std::sync::Once;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
};
use windows_sys::core::BOOL;

unsafe extern "system" {
    pub fn OnInitializeHook();
}
static HOOK_FLAG: Once = Once::new();

pub unsafe fn ProcHook() {
    HOOK_FLAG.call_once(|| unsafe { OnInitializeHook() });
}

pub trait WinApiHookHelper {
    type Args;
    type Ret;
}

pub unsafe fn MemoryVPPatch(dest: *mut c_void, bytes: &[u8; 5]) {
    VP::Patch_Address_List(dest, bytes);
}

macro_rules! define_winapi_hook {
    (
        $mod_name:ident,
        fn($($arg_name:ident: $arg_type:ty),*) -> $ret_type:ty
    ) => {
        pub mod $mod_name {
            use super::*;
            use std::sync::atomic::{AtomicPtr, Ordering};
            use std::ffi::c_void;

            pub type FuncType = unsafe extern "system" fn($($arg_type),*) -> $ret_type;

            pub static ORIG_FUNCTION: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

            pub static mut ORIG_CODE: [u8; 5] = [0; 5];

            pub unsafe extern "system" fn hook($($arg_name: $arg_type),*) -> $ret_type {
                unsafe {ProcHook();}

                let orig_ptr = ORIG_FUNCTION.load(Ordering::Relaxed);
                let orig_fn: FuncType = unsafe {std::mem::transmute(orig_ptr)};

                orig_fn($($arg_name),*)
            }

            pub unsafe extern "system" fn overwriting_hook($($arg_name: $arg_type),*) -> $ret_type {
                let orig_ptr = ORIG_FUNCTION.load(Ordering::Relaxed);
                let code_copy = unsafe { std::ptr::read(std::ptr::addr_of!(ORIG_CODE)) };
                unsafe { MemoryVPPatch(orig_ptr, &code_copy)};
                unsafe { hook($($arg_name),*) }
            }

            pub fn setup(orig_fn: FuncType, original_bytes: [u8; 5]) {
                ORIG_FUNCTION.store(orig_fn as *mut c_void, Ordering::Relaxed);
                unsafe {
                    std::ptr::write(std::ptr::addr_of_mut!(ORIG_CODE), original_bytes);
                }
            }
        }
    };
}

// WARNING: You can use the macro the old way, but that makes it
// so that you can't easily configure the function and the return type.
// Personally I think both solutions stink, but Rust isn't CPP and this
// is a port job by someone who has barely an idea of what they're doing.
// Nor do they understand CPP exactly...

// define_winapi_hook!(wrapped_function, fn() -> *mut c_void);
include!(concat!(env!("OUT_DIR"), "/generated_hook.rs"));

pub unsafe fn ReplaceFunction(funcPtr: *mut *mut c_void) {
    let mut dwProtect: DWORD = 0;
    unsafe {
        VirtualProtect(
            funcPtr as *const c_void,
            size_of::<*mut *mut c_void>(),
            PAGE_READWRITE,
            &mut dwProtect,
        );

        let target_addr = *funcPtr;
        wrapped_function::setup(
            std::mem::transmute::<*mut c_void, wrapped_function::FuncType>(target_addr),
            [0; 5],
        );

        *funcPtr = wrapped_function::hook as *mut c_void;

        VirtualProtect(
            funcPtr as *const c_void,
            size_of::<*mut *mut c_void>(),
            dwProtect,
            &mut dwProtect,
        );
    }
}

pub unsafe fn PatchIAT() -> bool {
    #[cfg(feature = "hooked_module")]
    const HOOKED_MODULE_NAME: &str = concat!(env!("module_name"), "\0");

    let instance: usize = {
        #[cfg(feature = "hooked_module")]
        {
            let mut handle = unsafe { GetModuleHandleA(HOOKED_MODULE_NAME.as_ptr()) };
            if handle.is_null() {
                unsafe { handle = GetModuleHandleA(std::ptr::null()) };
            }
            handle as usize
        }
        #[cfg(not(feature = "hooked_module"))]
        {
            unsafe { GetModuleHandleA(std::ptr::null()) as usize }
        }
    };

    if instance == 0 {
        return false;
    }

    let dosHeader = instance as *const IMAGE_DOS_HEADER;
    let ntHeader = (instance + (*dosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADER;

    // Original comment: Find IAT
    let import_dir =
        &(*ntHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.VirtualAddress == 0 {
        return false;
    }

    let mut pImport =
        (instance + import_dir.VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;

    // These for to_str() comparisons
    const LIBRARY_NAME: &str = env!("library_name");
    const FUNCTION_NAME: &str = env!("function_name");

    // These for WinAPI calls
    const LIBRARY_NAME_C: &str = concat!(env!("library_name"), "\0");
    const FUNCTION_NAME_C: &str = concat!(env!("function_name"), "\0");

    while (*pImport).Name != 0 {
        let name_ptr = (instance + (*pImport).Name as usize) as *const c_char;
        let c_str = unsafe { CStr::from_ptr(name_ptr) };

        if let Ok(lib_name) = c_str.to_str()
            && lib_name.eq_ignore_ascii_case(LIBRARY_NAME)
        {
            let firstThunk = unsafe { (*pImport).Anonymous.OriginalFirstThunk };
            if firstThunk != 0 {
                let mut pThunk = (instance + firstThunk as usize) as *const IMAGE_THUNK_DATA;

                let mut thunk_idx = 0;
                unsafe {
                    while (*pThunk).u1.AddressOfData != 0 {
                        let import_name_ptr = (instance + (*pThunk).u1.AddressOfData as usize)
                            as *const IMAGE_IMPORT_BY_NAME;
                        let name_ptr = &(*import_name_ptr).Name as *const i8;
                        let c_str_2 = CStr::from_ptr(name_ptr);

                        if let Ok(import_name) = c_str_2.to_str()
                            && import_name.eq(FUNCTION_NAME)
                        {
                            let pAddress =
                                (instance + (*pImport).FirstThunk as usize) as *mut *mut c_void;
                            ReplaceFunction(pAddress.add(thunk_idx));
                            return true;
                        }

                        pThunk = pThunk.add(1);
                        thunk_idx += 1;
                    }
                }
            } else {
                // Original comment:
                // This will only work if nobody else beats us to it - which is fine, because a fallback exists
                let tgt_module = GetModuleHandleA(LIBRARY_NAME_C.as_ptr());
                if tgt_module.is_null() {
                    return false;
                }
                let tgt_func_ptr = GetProcAddress(tgt_module, FUNCTION_NAME_C.as_ptr());
                let tgt_func = match tgt_func_ptr {
                    Some(f) => f as *mut c_void,
                    None => return false,
                };

                let mut pFunctions =
                    (instance + (*pImport).FirstThunk as usize) as *mut *mut c_void;

                while !(*pFunctions).is_null() {
                    if *pFunctions == tgt_func {
                        unsafe {
                            ReplaceFunction(pFunctions);
                        }
                        return true;
                    }

                    pFunctions = unsafe { pFunctions.add(1) }
                }
            }
        }

        pImport = unsafe { pImport.add(1) };
    }
    false
}

pub unsafe fn PatchIAT_ByPointers() -> bool {
    use Memory::VP;

    const LIBRARY_NAME_C: &str = concat!(env!("library_name"), "\0");
    const FUNCTION_NAME_C: &str = concat!(env!("function_name"), "\0");

    let tgt_module = GetModuleHandleA(LIBRARY_NAME_C.as_ptr());
    if tgt_module.is_null() {
        return false;
    }

    let tgt_func_ptr = GetProcAddress(tgt_module, FUNCTION_NAME_C.as_ptr());
    let hooked_func = match tgt_func_ptr {
        Some(f) => f as *mut c_void,
        None => return false,
    };

    wrapped_function::ORIG_FUNCTION.store(hooked_func, Relaxed);

    let mut original_bytes = [0u8; 5];
    std::ptr::copy_nonoverlapping(hooked_func as *const u8, original_bytes.as_mut_ptr(), 5);
    std::ptr::write_unaligned(
        std::ptr::addr_of_mut!(wrapped_function::ORIG_CODE),
        original_bytes,
    );

    #[cfg(target_pointer_width = "64")]
    todo!();
    #[cfg(target_pointer_width = "32")]
    VP::InjectHookType(
        hooked_func,
        wrapped_function::overwriting_hook,
        HookType::Jump,
    );

    true
}

pub unsafe fn InstallHooks() {
    let getStartupInfoHooked: bool = PatchIAT();
    if !getStartupInfoHooked {
        PatchIAT_ByPointers();
    }
}

// #[cfg(feature = "skip_initializeasi")]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DLLMain(
    _hinst: HINSTANCE,
    reason: DWORD,
    _reserved: *const c_void,
) -> BOOL {
    if (reason == DLL_PROCESS_ATTACH) {
        InstallHooks();
    }
    1
}

// unsafe extern "C" {
//     // #[cfg(feature = "skip_initializeasi")]
//     static InitCount: LONG;
//     // has to be declspec(dllexport) but _cdecl????? dont get it

// }

const RSC_REVISION_ID: &str = env!("revision_id");
const RSC_BUILD_ID: &str = env!("build_id");

static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn InitializeASI() {
    if IS_INITIALIZED.swap(true, SeqCst) {
        return;
    }

    InstallHooks();
}

#[unsafe(no_mangle)]
pub extern "C" fn GetBuildNumber() -> u32 {
    let revision_int = RSC_REVISION_ID.parse::<u32>().unwrap();
    let build_int = RSC_BUILD_ID.parse::<u32>().unwrap();
    (revision_int << 8) | build_int
}
