// I made heavy use of LLMs across this code. I did not just copy and paste.
// I tried my hand at it and asked it for clarification as I went.
// It is possible I missed something crucial
// I did learn a lot though, which is cool!
use std::{collections::VecDeque, ffi::c_char};

use windows_sys::Win32::{
    Foundation::HINSTANCE,
    System::{
        Diagnostics::Debug::IMAGE_SECTION_HEADER,
        Memory::{
            MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY,
            VirtualProtect, VirtualQuery,
        },
        SystemServices::IMAGE_DOS_HEADER,
    },
};

use crate::win_types::{DWORD, DWORD_PTR, IMAGE_NT_HEADER, LPCVOID, LPVOID, SIZE_T};

struct UnprotectData {
    m_queriedProtects: VecDeque<(LPVOID, SIZE_T, DWORD)>,
}

pub enum UnprotectedTarget {
    Section(Section),
    FullModule(FullModule),
}

pub struct Section {
    data: UnprotectData,
    m_located_section: bool,
}

pub struct FullModule {
    data: UnprotectData,
}

impl Section {
    fn new(h_instance: HINSTANCE, name: *const c_char) -> Self {
        unsafe {
            let ntHeader: *const IMAGE_NT_HEADER = (h_instance as *const u8)
                .add((*(h_instance as *const IMAGE_DOS_HEADER)).e_lfanew as usize)
                as *const IMAGE_NT_HEADER;
            let pSection: *const IMAGE_SECTION_HEADER = (&(*ntHeader).OptionalHeader as *const _
                as *const u8)
                .add((*ntHeader).FileHeader.SizeOfOptionalHeader as usize)
                as *const IMAGE_SECTION_HEADER;

            let num_sections: usize = (*ntHeader).FileHeader.NumberOfSections as usize;
            let mut current_pSection: *const IMAGE_SECTION_HEADER = pSection;
            let mut data_found: Option<UnprotectData> = None;

            for _ in 0..num_sections {
                let mut is_match: bool = true;

                _find_pSection_match(name, current_pSection, &mut is_match);

                if is_match {
                    let mut data = UnprotectData::new();
                    data.UnprotectRange(
                        (h_instance as usize + (*current_pSection).VirtualAddress as usize)
                            as DWORD_PTR,
                        (*current_pSection).Misc.VirtualSize as usize,
                    );
                    data_found = Some(data);
                    break;
                }

                current_pSection = current_pSection.add(1);
            }

            if let Some(data) = data_found {
                Self {
                    data,
                    m_located_section: true,
                }
            } else {
                Self {
                    data: UnprotectData::new(),
                    m_located_section: false,
                }
            }
        }
    }

    fn section_located(&self) -> bool {
        self.m_located_section
    }
}

fn _find_pSection_match(
    name: *const i8,
    current_pSection: *const IMAGE_SECTION_HEADER,
    is_match: &mut bool,
) {
    unsafe {
        for i in 0..8 {
            if *name.add(i) as u8 != (*current_pSection).Name[i] {
                if *name.add(i) as u8 == 0 && (*current_pSection).Name[i] == 0 {
                    break;
                }
                *is_match = false;
                break;
            }

            if *name.add(i) as u8 == 0 {
                break;
            }
        }
    }
}

impl FullModule {
    fn new(h_instance: HINSTANCE) -> Self {
        unsafe {
            let ntHeader: *const IMAGE_NT_HEADER = (h_instance as *const u8)
                .add((*(h_instance as *const IMAGE_DOS_HEADER)).e_lfanew as usize)
                as *const IMAGE_NT_HEADER;

            let mut data = UnprotectData::new();
            data.UnprotectRange(
                h_instance as DWORD_PTR,
                (*ntHeader).OptionalHeader.SizeOfImage as usize,
            );
            Self { data }
        }
    }
}

impl Drop for UnprotectData {
    fn drop(&mut self) {
        for it in &self.m_queriedProtects {
            unsafe {
                let mut dwOldProtect: DWORD = 0;
                VirtualProtect(it.0, it.1, it.2, &mut dwOldProtect);
            }
        }
    }
}

pub fn unprotect_section_or_full_module(
    h_instance: HINSTANCE,
    name: *const c_char,
) -> UnprotectedTarget {
    let section = Section::new(h_instance, name);

    if section.section_located() {
        UnprotectedTarget::Section(section)
    } else {
        UnprotectedTarget::FullModule(FullModule::new(h_instance))
    }
}

impl UnprotectData {
    pub fn new() -> Self {
        Self {
            m_queriedProtects: VecDeque::new(),
        }
    }

    pub fn UnprotectRange(&mut self, BaseAddress: DWORD_PTR, Size: SIZE_T) {
        unsafe {
            let mut QueriedSize: SIZE_T = 0;

            while QueriedSize < Size {
                let mut MemoryInf: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let mut dwOldProtect: DWORD = 0;

                VirtualQuery(
                    (BaseAddress + QueriedSize as u64) as LPCVOID,
                    &mut MemoryInf,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if MemoryInf.State == MEM_COMMIT
                    && (MemoryInf.Type & MEM_IMAGE) != 0
                    && (MemoryInf.Protect
                        & (PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                            | PAGE_READWRITE
                            | PAGE_WRITECOPY)
                        == 0)
                {
                    let wasExecutable: bool =
                        (MemoryInf.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ)) != 0;

                    VirtualProtect(
                        MemoryInf.BaseAddress,
                        MemoryInf.RegionSize,
                        if wasExecutable {
                            PAGE_EXECUTE_READWRITE
                        } else {
                            PAGE_READWRITE
                        },
                        &mut dwOldProtect,
                    );
                    self.m_queriedProtects.push_front((
                        MemoryInf.BaseAddress,
                        MemoryInf.RegionSize,
                        MemoryInf.Protect,
                    ));
                }
                QueriedSize += MemoryInf.RegionSize;
            }
        }
    }
}
