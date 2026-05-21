pub mod Memory {
    use std::cmp::PartialEq;
    use std::ffi::c_void;

    #[cfg(target_pointer_width = "32")]
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    #[cfg(target_pointer_width = "64")]
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    #[derive(PartialEq, Debug)]
    pub enum HookType {
        Call,
        Jump,
    }

    #[inline]
    pub unsafe fn DynBaseAddress<AT>(address: AT) -> AT {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let live_base: isize = GetModuleHandleA(std::ptr::null()) as isize;

            #[cfg(target_pointer_width = "64")]
            const base_address: isize = 0x140000000;
            #[cfg(target_pointer_width = "32")]
            const base_address: isize = 0x400000;

            std::mem::transmute_copy::<isize, AT>(
                &(std::mem::transmute_copy::<AT, isize>(&address) + (live_base - base_address)),
            )
        }
    }

    pub unsafe fn PatchAddressValue<AT, T>(address: AT, value: T) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointed sized"
            );
        }

        unsafe {
            let addr: usize = std::mem::transmute_copy(&address);
            std::ptr::write(addr as *mut T, value);
        }
    }

    pub unsafe fn PatchAddressList<AT>(address: AT, list: &[u8]) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let mut_ptr: *mut u8 = std::mem::transmute_copy(&address);
            std::ptr::copy_nonoverlapping(list.as_ptr(), mut_ptr, list.len());
        }
    }

    pub unsafe fn Read<Var, AT>(address: AT, var: &mut Var) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let addr: usize = std::mem::transmute_copy(&address);
            *var = std::ptr::read(addr as *const Var);
        }
    }

    pub unsafe fn Nop<AT>(address: AT, count: usize) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }
        unsafe {
            let addr: usize = std::mem::transmute_copy(&address);
            std::ptr::write_bytes(addr as *mut u8, 0x90, count);
        }
    }

    pub unsafe fn WriteOffsetValue<Var, AT>(address: AT, var: &Var, bytesAfterDisplacement: isize) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }
        unsafe {
            let dst: isize = std::mem::transmute_copy(&address);
            let src: isize = std::mem::transmute_copy(&var);

            let offset = bytesAfterDisplacement;

            let target = src - dst - (4 + offset);

            std::ptr::write(dst as *mut i32, target as i32);
        }
    }

    pub unsafe fn ReadOffsetValue<Var, AT>(
        address: AT,
        var: &mut Var,
        bytesAfterDisplacement: isize,
    ) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let src_addr: isize = std::mem::transmute_copy(&address);

            let offset = std::ptr::read(src_addr as *const i32) as isize;
            let extra_bytes = bytesAfterDisplacement;
            let dst_addr = src_addr + (4 + extra_bytes) + offset;

            std::ptr::copy_nonoverlapping(
                &dst_addr as *const isize as *const Var,
                var as *mut Var,
                1,
            );
        }
    }

    pub unsafe fn WriteMemDisplacement<Var, AT>(
        address: AT,
        var: &Var,
        bytesAfterDisplacement: isize,
    ) {
        unsafe {
            #[cfg(target_pointer_width = "64")]
            WriteOffsetValue(address, var, bytesAfterDisplacement);
            #[cfg(target_pointer_width = "32")]
            PatchAddressValue(address, var);
        }
    }

    pub unsafe fn ReadMemDisplacement<Var, AT>(
        address: AT,
        var: &mut Var,
        bytesAfterDisplacement: isize,
    ) {
        unsafe {
            #[cfg(target_pointer_width = "64")]
            ReadOffsetValue(address, var, bytesAfterDisplacement);
            #[cfg(target_pointer_width = "32")]
            Read(address, var);
        }
    }

    pub unsafe fn InterceptMemDisplacement<AT: Copy, Var>(
        address: AT,
        orig: &mut Var,
        var: &Var,
        bytesAfterDisplacement: isize,
    ) {
        unsafe {
            ReadMemDisplacement(address, orig, bytesAfterDisplacement);
            let target_ptr = var as *const Var;
            WriteMemDisplacement(address, &target_ptr, bytesAfterDisplacement);
        }
    }

    pub unsafe fn InjectHook<AT, Func>(address: AT, hook: Func) {
        unsafe {
            let addr: isize = std::mem::transmute_copy(&address);
            let func_addr: isize = std::mem::transmute_copy(&hook);
            WriteOffsetValue(addr + 1, &func_addr, 0);
        }
    }

    pub unsafe fn InjectHookType<AT, Func>(address: AT, hook: Func, r#type: HookType) {
        let opcode = if r#type == HookType::Jump {
            0xE9u8
        } else {
            0xE8u8
        };

        unsafe {
            let addr: usize = std::mem::transmute_copy(&address);
            let func_addr: isize = std::mem::transmute_copy(&hook);

            std::ptr::write(addr as *mut u8, opcode);
            InjectHook(address, func_addr);
        }
    }

    pub unsafe fn ReadCall<Func, AT>(address: AT, func: &mut Func) {
        unsafe {
            let addr: isize = std::mem::transmute_copy(&address);
            ReadOffsetValue(addr + 1, func, 0);
        }
    }

    pub unsafe fn ReadCallFrom<AT>(address: AT, offset: isize) -> *mut c_void {
        let mut addr = 0;
        unsafe {
            ReadCall(address, &mut addr);
            (addr as isize + offset) as *mut c_void
        }
    }

    pub unsafe fn InterceptCall<AT: Copy, Func>(address: AT, func: &mut Func, hook: Func) {
        unsafe {
            ReadCall(address, func);
            InjectHook(address, hook);
        }
    }

    pub unsafe fn MemEquals(address: usize, val: &[u8]) -> bool {
        unsafe {
            let mem_ptr = address as *const u8;
            let mem_slice = std::slice::from_raw_parts(mem_ptr, val.len());

            mem_slice == val
        }
    }

    pub unsafe fn Verify<AT>(address: AT, expected: usize) -> AT {
        const {
            assert!(std::mem::size_of::<AT>() == std::mem::size_of::<usize>());
        }
        unsafe {
            let addr: usize = std::mem::transmute_copy(&address);
            assert_eq!(addr, expected);
            address
        }
    }

    pub mod DynBase {
        use super::DynBaseAddress;
        use std::ffi::c_void;

        #[derive(PartialEq, Debug)]
        pub enum HookType {
            Call,
            Jump,
        }

        pub unsafe fn Patch_Address_Value<T, AT>(address: AT, value: T) {
            unsafe {
                super::PatchAddressValue(DynBaseAddress(address), value);
            }
        }

        pub unsafe fn Patch_Address_List<AT>(address: AT, list: &[u8]) {
            unsafe {
                super::PatchAddressList(DynBaseAddress(address), list);
            }
        }

        pub unsafe fn Read<Var, AT>(address: AT, var: &mut Var) {
            unsafe {
                super::Read(DynBaseAddress(address), var);
            }
        }

        pub unsafe fn Nop<AT>(address: AT, count: usize) {
            unsafe {
                super::Nop(DynBaseAddress(address), count);
            }
        }

        pub unsafe fn WriteOffsetValue<Var, AT>(
            address: AT,
            var: &Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::WriteOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn ReadOffsetValue<Var, AT>(
            address: AT,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::ReadOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn WriteMemDisplacement<Var, AT>(
            address: AT,
            var: &Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::WriteMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn ReadMemDisplacement<Var, AT>(
            address: AT,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::ReadMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn InterceptMemDisplacement<Var, AT: Copy>(
            address: AT,
            orig: &mut Var,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::InterceptMemDisplacement(
                    DynBaseAddress(address),
                    orig,
                    var,
                    bytesAfterDisplacement,
                );
            }
        }

        pub unsafe fn InjectHook<AT, Func>(address: AT, hook: Func) {
            unsafe {
                super::InjectHook(DynBaseAddress(address), hook);
            }
        }

        pub unsafe fn InjectHookType<AT, Func>(address: AT, hook: Func, r#type: HookType) {
            unsafe {
                super::InjectHookType(
                    DynBaseAddress(address),
                    hook,
                    // Why the f- do I need transmute here, it's an enum :l
                    std::mem::transmute::<HookType, super::HookType>(r#type),
                );
            }
        }

        pub unsafe fn ReadCall<Func, AT>(address: AT, func: &mut Func) {
            unsafe {
                super::ReadCall(DynBaseAddress(address), func);
            }
        }

        pub unsafe fn ReadCallFrom<AT>(address: AT, offset: isize) -> *mut c_void {
            unsafe { super::ReadCallFrom(DynBaseAddress(address), offset) }
        }

        pub unsafe fn InterceptCall<AT: Copy, Func>(address: AT, func: &mut Func, hook: Func) {
            unsafe { super::InterceptCall(DynBaseAddress(address), func, hook) }
        }

        pub unsafe fn MemEquals(address: usize, val: &[u8]) -> bool {
            unsafe { super::MemEquals(DynBaseAddress(address), val) }
        }

        pub unsafe fn Verify<AT>(address: AT, expected: usize) -> AT {
            unsafe { super::Verify(DynBaseAddress(address), expected) }
        }
    }

    pub mod VP {
        use super::DynBaseAddress;
        use crate::win_types::{DWORD, DWORD_PTR};
        use std::ffi::c_void;
        use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

        #[derive(PartialEq, Debug)]
        pub enum HookType {
            Call,
            Jump,
        }

        pub unsafe fn Patch_Address_Value<T, AT>(address: AT, value: T) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr = std::mem::transmute_copy::<AT, usize>(&address);
                VirtualProtect(
                    addr as *mut c_void,
                    size_of::<T>(),
                    PAGE_EXECUTE_READWRITE,
                    &mut dwProtect,
                );
                super::PatchAddressValue(DynBaseAddress(address), value);
                VirtualProtect(
                    addr as *mut c_void,
                    size_of::<T>(),
                    dwProtect,
                    &mut dwProtect,
                );
            }
        }

        pub unsafe fn Patch_Address_List<AT>(address: AT, list: &[u8]) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr: usize = std::mem::transmute_copy(&address);
                VirtualProtect(
                    addr as *mut c_void,
                    list.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut dwProtect,
                );
                super::PatchAddressList(DynBaseAddress(address), list);
                VirtualProtect(addr as *mut c_void, list.len(), dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn Read<Var, AT>(address: AT, var: &mut Var) {
            unsafe {
                super::Read(DynBaseAddress(address), var);
            }
        }

        pub unsafe fn Nop<AT>(address: AT, count: usize) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr: *mut c_void = std::mem::transmute_copy(&address);
                VirtualProtect(addr, count, PAGE_EXECUTE_READWRITE, &mut dwProtect);
                super::Nop(DynBaseAddress(address), count);
                VirtualProtect(addr, count, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn WriteOffsetValue<Var, AT>(
            address: AT,
            var: &Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr: *mut c_void = std::mem::transmute_copy(&address);
                VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, &mut dwProtect);
                super::WriteOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
                VirtualProtect(addr, 4, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn ReadOffsetValue<Var, AT>(
            address: AT,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::ReadOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn WriteMemDisplacement<Var, AT>(
            address: AT,
            var: &Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                let mut dwProtect: DWORD = 0;

                let addr: *mut c_void = std::mem::transmute_copy(&address);
                VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, &mut dwProtect);
                super::WriteMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
                VirtualProtect(addr, 4, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn ReadMemDisplacement<Var, AT>(
            address: AT,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                super::ReadMemDisplacement(DynBaseAddress(address), var, bytesAfterDisplacement);
            }
        }

        pub unsafe fn InterceptMemDisplacement<Var, AT: Copy>(
            address: AT,
            orig: &mut Var,
            var: &mut Var,
            bytesAfterDisplacement: isize,
        ) {
            unsafe {
                let mut dwProtect: DWORD = 0;

                let addr: *mut c_void = std::mem::transmute_copy(&address);
                VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &mut dwProtect);
                super::InterceptMemDisplacement(
                    DynBaseAddress(address),
                    orig,
                    var,
                    bytesAfterDisplacement,
                );
                VirtualProtect(addr, 5, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn InjectHook<AT, Func>(address: AT, hook: Func) {
            unsafe {
                let mut dwProtect: DWORD = 0;

                let addr: DWORD_PTR = std::mem::transmute_copy(&address);
                VirtualProtect(
                    (addr + 1) as *mut c_void,
                    4,
                    PAGE_EXECUTE_READWRITE,
                    &mut dwProtect,
                );
                super::InjectHook(DynBaseAddress(address), hook);
                VirtualProtect((addr + 1) as *mut c_void, 4, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn InjectHookType<AT, Func>(address: AT, hook: Func, r#type: HookType) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr: DWORD_PTR = std::mem::transmute_copy(&address);

                VirtualProtect(
                    (addr + 1) as *mut c_void,
                    5,
                    PAGE_EXECUTE_READWRITE,
                    &mut dwProtect,
                );

                super::InjectHookType(
                    DynBaseAddress(address),
                    hook,
                    // Why the f- do I need transmute here, it's an enum :l
                    std::mem::transmute::<HookType, super::HookType>(r#type),
                );

                VirtualProtect((addr + 1) as *mut c_void, 5, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn ReadCall<Func, AT>(address: AT, func: &mut Func) {
            unsafe {
                super::ReadCall(DynBaseAddress(address), func);
            }
        }

        pub unsafe fn ReadCallFrom<AT>(address: AT, offset: isize) -> *mut c_void {
            unsafe { super::ReadCallFrom(DynBaseAddress(address), offset) }
        }

        pub unsafe fn InterceptCall<AT: Copy, Func>(address: AT, func: &mut Func, hook: Func) {
            unsafe {
                let mut dwProtect: DWORD = 0;
                let addr: *mut c_void = std::mem::transmute_copy(&address);
                VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &mut dwProtect);
                super::InterceptCall(DynBaseAddress(address), func, hook);
                VirtualProtect(addr, 5, dwProtect, &mut dwProtect);
            }
        }

        pub unsafe fn MemEquals(address: usize, val: &[u8]) -> bool {
            unsafe { super::MemEquals(DynBaseAddress(address), val) }
        }

        pub unsafe fn Verify<AT>(address: AT, expected: usize) -> AT {
            unsafe { super::Verify(DynBaseAddress(address), expected) }
        }

        pub mod DynBase {
            pub enum HookType {
                Call,
                Jump,
            }

            use super::DynBaseAddress;
            use crate::MemoryMgr::Memory;
            use windows_sys::Win32::System::Diagnostics::Debug::ADDRESS;

            pub unsafe fn Patch_Address_Value<AT, T>(address: AT, value: T) {
                unsafe {
                    super::Patch_Address_Value(DynBaseAddress(address), value);
                }
            }

            pub unsafe fn Patch_Address_List<AT>(address: AT, list: &[u8]) {
                unsafe {
                    super::Patch_Address_List(DynBaseAddress(address), list);
                }
            }

            pub unsafe fn Read<Var, AT>(address: AT, var: &mut Var) {
                unsafe {
                    super::Read(DynBaseAddress(address), var);
                }
            }

            pub unsafe fn Nop<AT>(address: AT, count: usize) {
                unsafe {
                    super::Nop(address, count);
                }
            }

            pub unsafe fn WriteOffsetValue<Var, AT>(
                address: AT,
                var: &Var,
                bytesAfterDisplacement: isize,
            ) {
                unsafe {
                    super::WriteOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
                }
            }

            pub unsafe fn ReadOffsetValue<Var, AT>(
                address: AT,
                var: &mut Var,
                bytesAfterDisplacement: isize,
            ) {
                unsafe {
                    super::ReadOffsetValue(DynBaseAddress(address), var, bytesAfterDisplacement);
                }
            }

            pub unsafe fn WriteMemDisplacement<Var, AT>(
                address: AT,
                var: &Var,
                bytesAfterDisplacement: isize,
            ) {
                unsafe {
                    super::WriteMemDisplacement(
                        DynBaseAddress(address),
                        var,
                        bytesAfterDisplacement,
                    );
                }
            }

            pub unsafe fn ReadMemDisplacement<Var, AT>(
                address: AT,
                var: &mut Var,
                bytesAfterDisplacement: isize,
            ) {
                unsafe {
                    super::ReadMemDisplacement(
                        DynBaseAddress(address),
                        var,
                        bytesAfterDisplacement,
                    );
                }
            }

            pub unsafe fn InterceptMemDisplacement<Var, AT: Copy>(
                address: AT,
                orig: &mut Var,
                var: &mut Var,
                bytesAfterDisplacement: isize,
            ) {
                unsafe {
                    super::InterceptMemDisplacement(
                        DynBaseAddress(address),
                        orig,
                        var,
                        bytesAfterDisplacement,
                    );
                }
            }

            pub unsafe fn InjectHook<AT, Func>(address: AT, func: Func) {
                unsafe {
                    super::InjectHook(DynBaseAddress(address), func);
                }
            }

            pub unsafe fn InjectHookType<AT, Func>(address: AT, func: Func, r#type: HookType) {
                unsafe {
                    super::InjectHookType(
                        DynBaseAddress(address),
                        func,
                        std::mem::transmute::<HookType, super::HookType>(r#type),
                    );
                }
            }

            pub unsafe fn ReadCall<AT, Func>(address: AT, func: &mut Func) {
                unsafe {
                    Memory::ReadCall(DynBaseAddress(address), func);
                }
            }

            pub unsafe fn ReadCallFrom<AT>(address: AT, offset: isize) {
                unsafe {
                    Memory::ReadCallFrom(DynBaseAddress(address), offset);
                }
            }

            pub unsafe fn InterceptCall<AT: Copy, Func>(address: AT, func: &mut Func, hook: Func) {
                unsafe {
                    super::InterceptCall(DynBaseAddress(address), func, hook);
                }
            }

            pub unsafe fn MemEquals(address: usize, list: &[u8]) -> bool {
                unsafe { Memory::MemEquals(DynBaseAddress(address), list) }
            }

            pub unsafe fn Verify<AT>(address: AT, expected: usize) -> AT {
                unsafe { Memory::Verify(address, DynBaseAddress(expected)) }
            }
        }
    }
}
