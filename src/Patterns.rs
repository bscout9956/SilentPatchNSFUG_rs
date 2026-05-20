pub trait FnvConfig {
    const PRIME: u64;
    const OFFSET_BASIS: u64;
}

// LLM helped me with this, I don't understand it
pub struct BasicFnv1<C: FnvConfig> {
    _marker: std::marker::PhantomData<C>,
}

impl<C: FnvConfig> BasicFnv1<C> {
    pub fn hash(text: &[u8]) -> u64 {
        let mut hash: u64 = C::OFFSET_BASIS;
        for &it in text {
            // Permits overflows without a panic
            hash = hash.wrapping_mul(C::PRIME);
            hash ^= it as u64;
        }

        hash
    }
}

pub struct Fnv64Constants;
impl FnvConfig for Fnv64Constants {
    const PRIME: u64 = 1_099_511_628_211;
    const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
}

pub type basic_fnv_1 = BasicFnv1<Fnv64Constants>;

mod hook {
    use std::ffi::{c_char, c_void};
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
        pub fn new(&self, pointer: *mut c_void) -> Self {
            Self { m_pointer: pointer }
        }

        pub fn get<T>(&self, offset: isize) -> *mut T {
            unsafe {
                return self.m_pointer.offset(offset) as *mut T;
            }
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

            fn tol(ch: c_char) -> u8 {
                let byte = ch as u8;

                match byte {
                    b'A'..=b'F' => byte - b'A' + 10,
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => byte - b'0',
                }
            }

            for ch in pattern {
                let byte = *ch;
                match byte {
                    b' ' => {}
                    b'?' => {
                        data.push(0);
                        mask.push(0);
                    }
                    b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                        let thisDigit: u8 = tol(byte as i8);

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

    use crate::Patterns::hook::pattern_match;

    struct basic_pattern {
        m_bytes: Vec<u8>,
        m_mask: Vec<u8>,
        // TODO: Add CFG for patterns_use_hints
        m_matches: Vec<pattern_match>,

        m_matched: bool,

        m_rangeStart: usize,
        m_rangeEnd: usize,
    }

    impl basic_pattern {
        fn get_internal(&self, index: usize) -> pattern_match {
            return self.m_matches[index];
        }

        fn new_begin_end(begin: usize, end: Option<usize>) -> Self {
            Self {
                m_rangeStart: begin,
                m_rangeEnd: end.unwrap_or(0),
                m_bytes: Vec::new(),
                m_mask: Vec::new(),
                m_matches: Vec::new(),
                m_matched: false,
            }
        }

        fn new_pattern(pattern: &[u8]) -> Self {
            let base: usize = get_process_base();
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
            let mut pattern_instance = Self::new_begin_end(get_process_base(), None);
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
            // TODO: Add patterns use hints
            pattern_match::TransformPattern(pattern, &mut self.m_bytes, &mut self.m_mask);

            // TODO: Add patterns use hints

            // TODO: Only perform block if CAN_SERIALIZE_HITNS

            {
                // let range = getHints().equal_range(m_hash);
            }
        }

        // TODO: Unsure how to implement this part
        // explicit basic_pattern_impl(std::string_view pattern)
        // 		: basic_pattern_impl(get_process_base())
        // 	{
        // 		Initialize(std::move(pattern));
        // 	}
        // fn new()
    }

    fn get_process_base() -> usize {
        unsafe { GetModuleHandleA(std::ptr::null()) as usize }
    }
}

mod txn {}
