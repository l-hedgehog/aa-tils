//! Raw aarch64-Linux syscalls + bpf_attr builders (no libc crate, no crates.io
//! fetch). Attach mode needs only `bpf()`; init mode adds mount/execve later.

#![allow(dead_code)]

// aarch64 Linux syscall numbers (asm-generic/unistd.h)
pub const SYS_BPF: u64 = 280;
pub const SYS_MOUNT: u64 = 40;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_EXECVE: u64 = 221;
pub const SYS_SETSID: u64 = 112;
pub const SYS_PRCTL: u64 = 167;

// openat flags / path constants
pub const O_RDONLY: u64 = 0;
pub const O_DIRECTORY: u64 = 0x10000;
pub const AT_FDCWD: i64 = -100;
pub const AF_UNIX: u64 = 1;
pub const AF_INET: u64 = 2;

#[inline(always)]
unsafe fn syscall3(n: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc 0",
        in("x8") n,
        in("x0") a1,
        in("x1") a2,
        in("x2") a3,
        lateout("x0") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall4(n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc 0",
        in("x8") n,
        in("x0") a1,
        in("x1") a2,
        in("x2") a3,
        in("x3") a4,
        lateout("x0") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall5(n: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc 0",
        in("x8") n,
        in("x0") a1,
        in("x1") a2,
        in("x2") a3,
        in("x3") a4,
        in("x4") a5,
        lateout("x0") ret,
        options(nostack)
    );
    ret
}

fn check(ret: i64) -> Result<i64, i32> {
    if ret < 0 {
        Err(-ret as i32)
    } else {
        Ok(ret)
    }
}

/// bpf(cmd, attr, size) — `syscall(SYS_bpf, cmd, attr, size)`.
pub fn bpf(cmd: u32, attr: &[u8], size: u32) -> Result<i64, i32> {
    let ptr = attr.as_ptr() as u64;
    let ret = unsafe { syscall3(SYS_BPF, cmd as u64, ptr, size as u64) };
    check(ret)
}

/// mount(source, target, fstype, flags, data) — used by init mode.
pub fn mount(
    source: *const u8,
    target: *const u8,
    fstype: *const u8,
    flags: u64,
    data: u64, // NULL page/mountopts pointer; pass 0
) -> Result<i64, i32> {
    let ret = unsafe {
        syscall5(SYS_MOUNT, source as u64, target as u64, fstype as u64, flags, data)
    };
    check(ret)
}

/// openat(dirfd, path, flags, mode) — used to open the cgroup dir.
pub fn openat(dirfd: i64, path: &str, flags: u64, mode: u64) -> Result<i64, i32> {
    let ret = unsafe {
        syscall4(
            SYS_OPENAT,
            dirfd as u64,
            path.as_ptr() as u64,
            flags,
            mode,
        )
    };
    check(ret)
}

/// close(fd)
pub fn close(fd: i64) -> Result<i64, i32> {
    check(unsafe { syscall3(SYS_CLOSE, fd as u64, 0, 0) })
}

/// execve(path, argv, envp) — passes raw C nul-terminated string buffers as
/// argvptr/envptr (the caller keeps them alive). Never returns on success.
pub fn execve(path: *const u8, argv: &Vec<u64>, envp: &Vec<u64>) -> Result<i64, i32> {
    let ret = unsafe { syscall3(SYS_EXECVE, path as u64, argv.as_ptr() as u64, envp.as_ptr() as u64) };
    check(ret) // only returns on error
}

pub fn err_str(err: i32) -> String {
    let name = match err {
        1 => "EPERM",
        2 => "ENOENT",
        5 => "EIO",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        28 => "ENOSPC",
        _ => "EUNKNOWN",
    };
    format!("{} (-{})", name, err)
}

// ---------- bpf command + attribute constants ----------
pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_ATTACH: u32 = 8;

pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;

// prog / attach types (this 6.18 ABI)
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
pub const BPF_PROG_TYPE_XDP: u32 = 6;
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
pub const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
pub const BPF_CGROUP_UDP4_RECVMSG: u32 = 19;

/// bpf_attr field offsets (union bpf_attr, byte offsets)
pub mod attr {
    pub const MAP_TYPE: usize = 0;
    pub const MAP_KEY_SIZE: usize = 4;
    pub const MAP_VALUE_SIZE: usize = 8;
    pub const MAP_MAX_ENTRIES: usize = 12;
    pub const MAP_FLAGS: usize = 16;

    pub const PROG_TYPE: usize = 0;
    pub const INSN_CNT: usize = 4;
    pub const INSNS: usize = 8;
    pub const LICENSE: usize = 16;
    pub const LOG_LEVEL: usize = 24;
    pub const LOG_SIZE: usize = 28;
    pub const LOG_BUF: usize = 32;
    pub const EXPECTED_ATTACH_TYPE: usize = 68;

    pub const TARGET_FD: usize = 0;
    pub const ATTACH_BPF_FD: usize = 4;
    pub const ATTACH_TYPE: usize = 8;

    pub const MAP_FD: usize = 0;
    pub const KEY: usize = 8;
    pub const VALUE: usize = 16;
    pub const FLAGS: usize = 24;
}

fn put_u32(attr: &mut [u8], off: usize, v: u32) {
    attr[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(attr: &mut [u8], off: usize, v: u64) {
    attr[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Create a map; returns its fd.
pub fn bpf_map_create(mtype: u32, key: u32, val: u32, max: u32, flags: u32) -> Result<i64, i32> {
    let mut a = [0u8; 96];
    put_u32(&mut a, attr::MAP_TYPE, mtype);
    put_u32(&mut a, attr::MAP_KEY_SIZE, key);
    put_u32(&mut a, attr::MAP_VALUE_SIZE, val);
    put_u32(&mut a, attr::MAP_MAX_ENTRIES, max);
    put_u32(&mut a, attr::MAP_FLAGS, flags);
    bpf(BPF_MAP_CREATE, &a, 80)
}

/// Write one ARRAY element. key/value are raw LE bytes.
pub fn bpf_map_update(map_fd: i64, key: &[u8], val: &[u8]) -> Result<i64, i32> {
    let mut a = [0u8; 64];
    put_u32(&mut a, attr::MAP_FD, map_fd as u32);
    put_u64(&mut a, attr::KEY, key.as_ptr() as u64);
    put_u64(&mut a, attr::VALUE, val.as_ptr() as u64);
    bpf(BPF_MAP_UPDATE_ELEM, &a, 32)
}

/// Read one map element into `value_size` bytes (value ptr user-supplied).
pub fn bpf_map_lookup(map_fd: i64, key: &[u8], value: &mut [u8]) -> Result<i64, i32> {
    let mut a = [0u8; 64];
    put_u32(&mut a, attr::MAP_FD, map_fd as u32);
    put_u64(&mut a, attr::KEY, key.as_ptr() as u64);
    put_u64(&mut a, attr::VALUE, value.as_ptr() as u64);
    bpf(BPF_MAP_LOOKUP_ELEM, &a, 32)
}

const LOG_BUF_LEN: usize = 1 << 20;

static mut LAST_LOG: [u8; LOG_BUF_LEN] = [0; LOG_BUF_LEN];
static mut LAST_LOG_LEN: u32 = 0;

/// Load a program section; returns its fd. On failure the verifier log is
/// retained for `last_log()`.
pub fn bpf_prog_load(
    prog_type: u32,
    insns: &[u8],
    license: &[u8],
    expected_attach: u32,
) -> Result<i64, i32> {
    let mut attr = [0u8; 256];
    put_u32(&mut attr, attr::PROG_TYPE, prog_type);
    put_u32(&mut attr, attr::INSN_CNT, (insns.len() / 8) as u32);
    put_u64(&mut attr, attr::INSNS, insns.as_ptr() as u64);
    put_u64(&mut attr, attr::LICENSE, license.as_ptr() as u64);
    put_u32(&mut attr, attr::LOG_LEVEL, 1);
    put_u32(&mut attr, attr::LOG_SIZE, LOG_BUF_LEN as u32);
    put_u64(&mut attr, attr::LOG_BUF, core::ptr::addr_of!(LAST_LOG) as *const u8 as u64);
    put_u32(&mut attr, attr::EXPECTED_ATTACH_TYPE, expected_attach);
    let res = bpf(BPF_PROG_LOAD, &attr, 128);
    // record how much the kernel wrote (it fills from the start)
    unsafe {
        for i in 0..LOG_BUF_LEN {
            if LAST_LOG[i] == 0 {
                LAST_LOG_LEN = i as u32;
                break;
            }
        }
    }
    res
}

/// Verifier log captured by the most recent `bpf_prog_load`.
pub fn last_log() -> &'static [u8] {
    unsafe { &LAST_LOG[..LAST_LOG_LEN as usize] }
}

/// Attach a program to a cgroup v2 directory fd.
pub fn bpf_prog_attach(target_fd: i64, prog_fd: i64, attach_type: u32) -> Result<i64, i32> {
    let mut a = [0u8; 32];
    put_u32(&mut a, attr::TARGET_FD, target_fd as u32);
    put_u32(&mut a, attr::ATTACH_BPF_FD, prog_fd as u32);
    put_u32(&mut a, attr::ATTACH_TYPE, attach_type);
    bpf(BPF_PROG_ATTACH, &a, 20)
}
