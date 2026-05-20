use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::win_types::IMAGE_NT_HEADER;

pub trait FnvConfig {
    const PRIME: u64;
    const OFFSET_BASIS: u64;
}

pub struct BasicFnv1<const PRIME: u64, const OFFSET_BASIS: u64>;

// LLM helped me with this, I don't understand it
impl<const PRIME: u64, const OFFSET_BASIS: u64> BasicFnv1<PRIME, OFFSET_BASIS> {
    pub fn hash(text: &[u8]) -> u64 {
        let mut hash: u64 = OFFSET_BASIS;
        for &it in text {
            // Permits overflows without a panic
            hash = hash.wrapping_mul(PRIME);
            hash ^= it as u64;
        }
        hash
    }
}

pub type fnv_1 = BasicFnv1<1_099_511_628_211, 14_695_981_039_346_656_037>;

mod hook {
    use std::ffi::c_void;
    #[cfg(feature = "patterns_use_hints")]
    use std::{collections::BTreeMap, sync::Mutex};

    struct assert_err_policy;

    impl assert_err_policy {
        fn count(countMatches: bool) {
            assert!(countMatches)
        }
    }

    // TODO: Pattern enable exceptions

    #[derive(Copy, Clone)]
    pub struct pattern_match {
        m_pointer: *mut c_void,
    }

    impl pattern_match {
        pub fn new(pointer: *mut c_void) -> Self {
            Self { m_pointer: pointer }
        }

        pub fn get<T>(&self, offset: isize) -> *mut T {
            unsafe { self.m_pointer.offset(offset) as *mut T }
        }

        // TODO: Verify, is this what we want?
        pub fn get_usize(&self, offset: isize) -> *mut usize {
            self.get::<c_void>(offset) as *mut usize
        }

        #[cfg(feature = "patterns_use_hints")]
        pub fn getHints() -> &'static Mutex<BTreeMap<u64, Vec<usize>>> {
            use std::{collections::BTreeMap, sync::OnceLock};

            static hints: OnceLock<Mutex<BTreeMap<u64, Vec<usize>>>> = OnceLock::new();
            hints.get_or_init(|| Mutex::new(BTreeMap::new()))
        }

        pub fn TransformPattern(pattern: &[u8], data: &mut Vec<u8>, mask: &mut Vec<u8>) {
            let mut tempDigit: u8 = 0;
            let mut tempFlag: bool = false;

            for &byte in pattern {
                match byte {
                    b' ' => continue,
                    b'?' => {
                        data.push(0);
                        mask.push(0);
                    }
                    b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                        let thisDigit = match byte {
                            b'A'..=b'F' => byte - b'A' + 10,
                            b'a'..=b'f' => byte - b'a' + 10,
                            _ => byte - b'0',
                        };

                        if !tempFlag {
                            tempDigit = thisDigit << 4;
                            tempFlag = true;
                        } else {
                            tempDigit |= thisDigit;
                            tempFlag = false;
                            data.push(tempDigit);
                            mask.push(0xFF);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

mod details {
    // ptrdiff_t get_process_base(); ???

    use std::os::raw::c_void;

    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    #[cfg(feature = "patterns_use_hints")]
    use crate::Patterns::fnv_1;
    use crate::Patterns::{executable_meta, hook::pattern_match};

    struct basic_pattern {
        m_bytes: Vec<u8>,
        m_mask: Vec<u8>,
        m_matches: Vec<pattern_match>,

        #[cfg(feature = "patterns_use_hints")]
        m_hash: u64,

        m_matched: bool,

        m_rangeStart: usize,
        m_rangeEnd: usize,
    }

    impl basic_pattern {
        fn get_internal(&self, index: usize) -> pattern_match {
            self.m_matches[index]
        }

        fn new_begin_end(begin: usize, end: Option<usize>) -> Self {
            Self {
                m_rangeStart: begin,
                m_rangeEnd: end.unwrap_or(0),
                #[cfg(feature = "patterns_use_hints")]
                m_hash: 0,
                m_bytes: Vec::new(),
                m_mask: Vec::new(),
                m_matches: Vec::new(),
                m_matched: false,
            }
        }

        fn new_pattern(pattern: &[u8]) -> Self {
            let base: usize = get_process_base() as usize;
            let mut pattern_instance = Self::new_begin_end(base, None);
            pattern_instance.Initialize(pattern);
            pattern_instance
        }

        fn new_module(module: *const c_void, pattern: &[u8]) -> Self {
            let address = module as usize;
            let mut pattern_instance = Self::new_begin_end(address, None);
            pattern_instance.Initialize(pattern);
            pattern_instance
        }

        fn new_pattern_begin_end(begin: usize, end: usize, pattern: &[u8]) -> Self {
            let mut pattern_instance = Self::new_begin_end(begin, Some(end));
            pattern_instance.Initialize(pattern);
            pattern_instance
        }

        // Pretransformed patterns
        fn new_pattern_bytes_mask(bytes: &[u8], mask: &[u8]) -> Self {
            assert!(bytes.len() == mask.len());
            let mut pattern_instance = Self::new_begin_end(get_process_base() as usize, None);
            pattern_instance.m_bytes = bytes.to_vec();
            pattern_instance.m_mask = mask.to_vec();
            pattern_instance
        }

        fn new_module_bytes_mask(module: *const c_void, bytes: &[u8], mask: &[u8]) -> Self {
            assert!(bytes.len() == mask.len());
            let mut pattern_instance = Self::new_begin_end(module as usize, None);
            pattern_instance.m_bytes = bytes.to_vec();
            pattern_instance.m_mask = mask.to_vec();
            pattern_instance
        }

        fn new_begin_end_bytes_mask(begin: usize, end: usize, bytes: &[u8], mask: &[u8]) -> Self {
            assert!(bytes.len() == mask.len());
            let mut pattern_instance = Self::new_begin_end(begin, Some(end));
            pattern_instance.m_bytes = bytes.to_vec();
            pattern_instance.m_mask = mask.to_vec();
            pattern_instance
        }

        #[cfg(feature = "patterns_use_hints")]
        #[cfg(feature = "patterns_can_serialize_hints")]
        fn hint(hash: u64, address: usize) {
            use crate::Patterns::hook;

            let mutex = hook::pattern_match::getHints();
            let mut hints = mutex.lock().unwrap();

            let addresses = hints.entry(hash).or_insert_with(|| Vec::new());
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }

        fn Initialize(&mut self, pattern: &[u8]) {
            #[cfg(feature = "patterns_use_hints")]
            // Attributes on expressions are "experimental" in rust atm, so we just use a block to "bypass" it
            // In practicality we're still assigning the value so it should be ok.
            {
                self.m_hash = fnv_1::hash(pattern);
            }

            pattern_match::TransformPattern(pattern, &mut self.m_bytes, &mut self.m_mask);

            // Needed some LLM help for this portion
            #[cfg(feature = "patterns_use_hints")]
            {
                #[cfg(feature = "patterns_can_serialize_hints")]
                let check_hints =
                    self.m_rangeStart == unsafe { GetModuleHandleA(std::ptr::null()) as usize };

                #[cfg(not(feature = "patterns_can_serialize_hints"))]
                let check_hints = true;
                if check_hints {
                    let mutex = pattern_match::getHints();
                    let hints = mutex.lock().unwrap();

                    if let Some(addresses) = hints.get(&self.m_hash) {
                        for &address in addresses {
                            self.consider_hint(address);
                        }

                        if !self.m_matches.is_empty() {
                            self.m_matched = true;
                        }
                    }
                }
            }
        }

        fn consider_hint(&mut self, offset: usize) -> bool {
            let ptr = offset as *const u8;

            #[cfg(feature = "patterns_can_serialize_hints")]
            {
                let pattern: &[u8] = &self.m_bytes;
                let mask: &[u8] = &self.m_mask;

                let mut i: usize = 0;
                let j: usize = self.m_mask.len();
                while i < j {
                    let byte = unsafe { *ptr.add(i) };
                    if pattern[i] != (byte & mask[i]) {
                        return false;
                    }
                    i += 1;
                }
            }

            self.m_matches.push(pattern_match::new(ptr as *mut c_void));

            true
        }

        fn matchSuccess(&self, address: usize, max_count: usize) -> bool {
            #[cfg(feature = "patterns_use_hints")]
            {
                let mutex = pattern_match::getHints();
                let mut hints = mutex.lock().unwrap();
                hints.entry(self.m_hash).or_default().push(address);
            }
            #[cfg(not(feature = "patterns_use_hints"))]
            {
                // TODO: Verify this
                address = address as *const c_void;
            }

            self.m_matches.len() == max_count
        }

        fn EnsureMatches(&mut self, maxCount: usize) {
            if self.m_matched {
                return;
            }

            let executable: executable_meta = if self.m_rangeStart != 0 && self.m_rangeEnd != 0 {
                executable_meta::new_begin_end(self.m_rangeStart, self.m_rangeEnd)
            } else {
                executable_meta::new(self.m_rangeStart)
            };

            let pattern: &Vec<u8> = &self.m_bytes;
            let mask: &Vec<u8> = &self.m_mask;
            let mask_size: usize = self.m_mask.len();
            let last_wild: Option<usize> = self.m_mask.iter().rposition(|&b| b != 0xFF);

            let fill_value: isize = last_wild.map_or(-1, |idx| idx as isize);

            let mut Last: [isize; 256] = [fill_value; 256];

            for i in 0..mask_size {
                let byte_val = pattern[i] as usize;
                if Last[byte_val] < i as isize {
                    Last[byte_val] = i as isize;
                }
            }

            let mut i: usize = executable.begin();
            let end: usize = executable.end() - mask_size;

            while i <= end {
                let ptr = i as *const u8;
                let mut j: isize = (mask_size - 1) as isize;

                unsafe {
                    while j >= 0 && pattern[j as usize] == (*ptr.add(j as usize) & mask[j as usize])
                    {
                        j -= 1;
                    }
                }

                if j < 0 {
                    self.m_matches.push(pattern_match::new(ptr as *mut c_void));

                    if self.matchSuccess(i, maxCount) {
                        break;
                    }
                    i += 1;
                } else {
                    unsafe {
                        let bad_char: u8 = *ptr.add(j as usize);
                        let shift: isize = j - Last[bad_char as usize];

                        i += std::cmp::max(1, shift) as usize;
                    }
                }
            }

            self.m_matched = true;
        }
    }

    fn get_process_base() -> isize {
        unsafe { GetModuleHandleA(std::ptr::null()) as isize }
    }
}

mod txn {}

struct executable_meta {
    m_begin: usize,
    m_end: usize,
}

impl executable_meta {
    fn new(module: usize) -> Self {
        unsafe {
            let dosHeader: *const IMAGE_DOS_HEADER = module as *const IMAGE_DOS_HEADER;
            let ntHeader: *const IMAGE_NT_HEADER =
                (module + (*dosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADER;

            let m_begin = module + (*ntHeader).OptionalHeader.BaseOfCode as usize;
            let mut meta = Self {
                m_begin,
                m_end: m_begin + (*ntHeader).OptionalHeader.SizeOfCode as usize,
            };

            // Original comment:
            // Executables with DRM bypassed may lie in their SizeOfCode and underreport severely
            // We can somewhat detect this by checking if the code entry point is past
            // these boundaries. It's not perfect, but it's safe.
            let entryPoint: usize =
                module + (*ntHeader).OptionalHeader.AddressOfEntryPoint as usize;

            if entryPoint >= m_begin && entryPoint <= meta.m_end {
                return meta;
            }

            // Original comment:
            // Alternate heuristics - scan the entire executable, minus headers
            let sizeOfHeaders: usize = (*ntHeader).OptionalHeader.SizeOfHeaders as usize;
            meta.m_begin = module + sizeOfHeaders;
            meta.m_end = module + (*ntHeader).OptionalHeader.SizeOfImage as usize - sizeOfHeaders;

            meta
        }
    }

    fn new_begin_end(begin: usize, end: usize) -> Self {
        Self {
            m_begin: begin,
            m_end: end,
        }
    }

    #[inline]
    fn begin(&self) -> usize {
        self.m_begin
    }

    #[inline]
    fn end(&self) -> usize {
        self.m_end
    }
}
