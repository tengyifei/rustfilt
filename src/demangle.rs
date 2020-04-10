// Copyright 2016 Mozilla
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate regex;
pub extern crate rustc_demangle;

pub use self::rustc_demangle::demangle;
use self::regex::{Regex, Captures};

use std::borrow::Cow;
use std::io::{self, BufRead, Write};
use std::os::raw::c_char;
use std::ffi::{CString, CStr};

// NOTE: Use [[:alnum::]] instead of \w to only match ASCII word characters, not unicode
thread_local!(static MANGLED_NAME_PATTERN: Regex = Regex::new(r"_(ZN|R)[\$\._[:alnum:]]*").unwrap());

#[inline] // Except for the nested functions (which don't count), this is a very small function
pub fn demangle_line(line: &str, include_hash: bool) -> Cow<str> {
    MANGLED_NAME_PATTERN.with(|pattern| {
        pattern.replace_all(line, |captures: &Captures| {
            let demangled = demangle(&captures[0]);
            if include_hash {
                demangled.to_string()
            } else {
                // Use alternate formatting to exclude the hash from the result
                format!("{:#}", demangled)
            }
        })
    })
}

pub fn demangle_stream<R: BufRead, W: Write>(input: &mut R, output: &mut W, include_hash: bool) -> io::Result<()> {
    // NOTE: this is actually more efficient than lines(), since it re-uses the buffer
    let mut buf = String::new();
    while input.read_line(&mut buf)? > 0 {
        {
            // NOTE: This includes the line-ending, and leaves it untouched
            let demangled_line = demangle_line(&buf, include_hash);
            if cfg!(debug_assertions) && buf.ends_with('\n') {
                let line_ending = if buf.ends_with("\r\n") { "\r\n" } else { "\n" };
                debug_assert!(demangled_line.ends_with(line_ending), "Demangled line has incorrect line ending");
            }
            output.write_all(demangled_line.as_bytes())?;
        }
        buf.clear(); // Reset the buffer's position, without freeing it's underlying memory
    }
    Ok(()) // Successfully hit EOF
}

#[no_mangle]
pub extern "C" fn demangle_rust_symbol(mangled: *const c_char) -> *mut c_char {
    unsafe {
        let mangled_slice = CStr::from_ptr(mangled);
        let demangled = demangle_line(mangled_slice.to_str().unwrap(), false);
        let c_str = CString::new(demangled.into_owned()).unwrap();
        return c_str.into_raw();
    }
}

#[no_mangle]
pub extern "C" fn recycle_demangle_result(demangled: *mut c_char) {
    unsafe {
        let _ = CString::from_raw(demangled);
    }
}

