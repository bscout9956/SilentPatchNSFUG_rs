pub mod Memory {
    use std::ffi::c_void;

    #[cfg(target_pointer_width = "32")]
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    #[cfg(target_pointer_width = "64")]
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

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

    pub unsafe fn Patch_Address_Value<AT, T>(address: AT, value: T) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointed sized"
            );
        }

        unsafe {
            let addr = std::mem::transmute_copy::<AT, usize>(&address);
            std::ptr::write(addr as *mut T, value);
        }
    }

    pub unsafe fn Patch_Address<AT>(address: AT, list: &[u8]) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let mut_ptr = std::mem::transmute_copy::<AT, usize>(&address) as *mut u8;
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
            let addr = std::mem::transmute_copy::<AT, usize>(&address);
            std::ptr::read(addr as *const Var);
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
            let addr = std::mem::transmute_copy::<AT, usize>(&address);
            std::ptr::write_bytes(addr as *mut u8, 0x90, count);
        }
    }

    pub unsafe fn WriteOffsetValue<Var, AT>(
        address: AT,
        var: &Var,
        bytesAfterDisplacement: Option<isize>,
    ) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }
        unsafe {
            let dst = std::mem::transmute_copy::<AT, isize>(&address);
            let src = std::mem::transmute_copy::<Var, isize>(&var);

            let offset = bytesAfterDisplacement.unwrap_or(0);

            let target = src - dst - (4 + offset);

            std::ptr::write(dst as *mut i32, target as i32);
        }
    }

    pub unsafe fn ReadOffsetValue<Var, AT>(
        address: AT,
        var: &mut Var,
        bytesAfterDisplacement: Option<isize>,
    ) {
        const {
            assert!(
                std::mem::size_of::<AT>() == std::mem::size_of::<usize>(),
                "AT must be pointer sized"
            );
        }

        unsafe {
            let src_addr = std::mem::transmute_copy::<AT, isize>(&address);

            let offset = std::ptr::read(src_addr as *const i32) as isize;
            let extra_bytes = bytesAfterDisplacement.unwrap_or(0);
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
        var: Var,
        bytesAfterDisplacement: Option<isize>,
    ) {
        unsafe {
            #[cfg(target_pointer_width = "64")]
            WriteOffsetValue(address, var, bytesAfterDisplacement);
            #[cfg(target_pointer_width = "32")]
            Patch_Address_Value(address, var);
        }
    }

    pub unsafe fn ReadMemDisplacement<Var, AT>(
        address: AT,
        var: &mut Var,
        bytesAfterDisplacement: Option<isize>,
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
        bytesAfterDisplacement: Option<isize>,
    ) {
        unsafe {
            ReadMemDisplacement(address, orig, bytesAfterDisplacement);
            let target_ptr = var as *const Var;
            WriteMemDisplacement(address, target_ptr, bytesAfterDisplacement);
        }
    }

    // RESUME
    pub unsafe fn InjectHook<AT, Func>(address: AT, hook: Func) {
        unsafe {
            WriteOffsetValue((address + 1) as isize, hook, Some(0));
        }
    }
}
