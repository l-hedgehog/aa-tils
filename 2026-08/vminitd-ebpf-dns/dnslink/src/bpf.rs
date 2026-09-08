//! Raw aarch64-Linux BPF syscalls + bpf_attr builders.

// aarch64 Linux syscall number (asm-generic/unistd.h)
pub const SYS_BPF: u64 = 280;

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

/// Readable name for a raw errno value ("File exists (os error 17)" etc.).
pub fn err_str(err: i32) -> String {
    format!("{}", std::io::Error::from_raw_os_error(err))
}

// ---------- bpf command + attribute constants ----------
pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_ATTACH: u32 = 8;

// prog / attach types (this 6.18 ABI)
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
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
