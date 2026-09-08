//! Thin safe-ish wrappers around the handful of non-bpf libc syscalls dnslink
//! needs, so callers never juggle raw pointers / C strings. All return
//! `io::Result<()>`, preserving the OS errno in the error.

use std::ffi::CString;
use std::io::{self, Error, ErrorKind};

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| Error::new(ErrorKind::InvalidInput, "string contains a NUL byte"))
}

/// mount(source, target, fstype, flags) with data=NULL (no call site uses
/// mount options today; easy to extend if needed). Ok(()) on success.
pub fn mount(source: &str, target: &str, fstype: &str, flags: u32) -> io::Result<()> {
    let src = cstr(source)?;
    let tgt = cstr(target)?;
    let fst = cstr(fstype)?;
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            flags as libc::c_ulong,
            core::ptr::null::<libc::c_void>(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

/// execve(path, argv, envp). `argv[0]` is the program name (callers must pass
/// the path first if that's what the program should see). Replaces the process
/// image; only returns `Err` (on success execve never returns).
pub fn execve(path: &str, argv: &[&str], envp: &[&str]) -> io::Result<()> {
    let path_c = cstr(path)?;
    let argv_c: Vec<CString> = argv.iter().map(|a| cstr(a)).collect::<io::Result<_>>()?;
    let envp_c: Vec<CString> = envp.iter().map(|a| cstr(a)).collect::<io::Result<_>>()?;

    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp_c.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(core::ptr::null());

    let r = unsafe { libc::execve(path_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    if r == 0 {
        Ok(()) // unreachable on success
    } else {
        Err(Error::last_os_error())
    }
}
