//! The attach-mode loader: parse the embedded .o, create maps, populate cfg,
//! relocate map fds, BPF_PROG_LOAD each hook, BPF_PROG_ATTACH to a cgroup.

use crate::bpf;
use crate::elf::Elf;

/// One redirect rule (on-disk ABI: `<IIHH`, 12 bytes).
pub struct Rule {
    pub requested_ip: u32, // BE numeric (a.b.c.d -> a<<24|b<<16|c<<8|d), stored native
    pub actual_ip: u32,
    pub requested_port: u16,
    pub actual_port: u16,
}

/// Program descriptors derived from section names.
pub struct Hook {
    pub name: String,
    pub prog_type: u32,
    pub attach_type: u32,
    pub _hit_key: u32,
}

pub const HOOKS: &[(&str, u32, u32, u32)] = &[
    // (section suffix, prog_type, attach_type, hit_key)
    ("connect4", bpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR, bpf::BPF_CGROUP_INET4_CONNECT, 0),
    ("udp4_sendmsg", bpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR, bpf::BPF_CGROUP_UDP4_SENDMSG, 1),
    ("udp4_recvmsg", bpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR, bpf::BPF_CGROUP_UDP4_RECVMSG, 2),
];

fn prog_for(section: &str) -> Option<Hook> {
    for (sfx, pt, at, key) in HOOKS {
        if let Some(rest) = section.strip_prefix("cgroup/") {
            if rest == *sfx {
                return Some(Hook {
                    name: section.to_string(),
                    prog_type: *pt,
                    attach_type: *at,
                    _hit_key: *key,
                });
            }
        }
    }
    None
}

/// Wrap a mapped error with a little context.
fn fail<T>(ctx: &str, e: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("{}: {}", ctx, e))
}

pub struct Loaded {
    pub hooks: Vec<Hook>,
    pub hit_map_fd: i64,
}

/// Parse the object, create its maps, populate cfg, load and attach all
/// cgroup hooks that `wanted` allows. Returns the hit_cnt map fd.
pub fn load_and_attach(
    obj: &[u8],
    cgroup_dir_fd: i64,
    rules: &Vec<(u32, Rule)>,
    wanted: &[&str],
    verbose: bool,
) -> Result<Loaded, String> {
    let elf = Elf::new(obj).ok_or("not a valid ELF/BPF object")?;

    // ---- maps ----------------------------------------------------------
    let maps_sec = elf.find(".maps").ok_or("no .maps section")?;
    let maps_sh = elf.shdr(maps_sec).unwrap();
    let mut name_fd: Vec<(String, i64)> = Vec::new();
    for (nm, sym) in elf.symtab() {
        if sym.shndx == maps_sec as i32 {
            let off = maps_sh.off + sym.value as usize;
            let d = &obj[off..off + 20];
            let m_type = u32::from_le_bytes(d[0..4].try_into().unwrap());
            let m_key = u32::from_le_bytes(d[4..8].try_into().unwrap());
            let m_val = u32::from_le_bytes(d[8..12].try_into().unwrap());
            let m_max = u32::from_le_bytes(d[12..16].try_into().unwrap());
            let m_flags = u32::from_le_bytes(d[16..20].try_into().unwrap());
            let fd = bpf::bpf_map_create(m_type, m_key, m_val, m_max, m_flags)
                .map_err(|e| format!("map_create {}: {}", &nm, bpf::err_str(e)))?;
            if verbose {
                println!("  map {}: fd={} type={} key={} val={} max={}", nm, fd, m_type, m_key, m_val, m_max);
            }
            name_fd.push((nm, fd));
        }
    }
    let fd_of = |name: &str| -> Option<i64> {
        name_fd.iter().find(|(n, _)| n.as_str() == name).map(|(_, fd)| *fd)
    };

    let cfg_fd = fd_of("cfg_map").ok_or("no cfg_map symbol")?;
    let hit_fd = fd_of("hit_cnt").ok_or("no hit_cnt symbol")?;

    // ---- populate cfg_map ----------------------------------------------
    for (idx, rule) in rules {
        let mut val = [0u8; 12];
        // IPs are stored in network-octet order (`7f 00 08 06` for 127.0.8.6);
        // aton() returns a BE integer, so to_be_bytes() restores that order.
        val[0..4].copy_from_slice(&rule.requested_ip.to_be_bytes());
        val[4..8].copy_from_slice(&rule.actual_ip.to_be_bytes());
        val[8..10].copy_from_slice(&rule.requested_port.to_le_bytes());
        val[10..12].copy_from_slice(&rule.actual_port.to_le_bytes());
        bpf::bpf_map_update(cfg_fd, &idx.to_le_bytes(), &val)
            .map_err(|e| format!("cfg update key {}: {}", idx, bpf::err_str(e)))?;
        if verbose {
            println!(
                "  cfg[{}]: {}.{}.{}.{}:{} <-> {}.{}.{}.{}:{}",
                idx,
                (rule.requested_ip >> 24) & 0xff,
                (rule.requested_ip >> 16) & 0xff,
                (rule.requested_ip >> 8) & 0xff,
                rule.requested_ip & 0xff,
                rule.requested_port,
                (rule.actual_ip >> 24) & 0xff,
                (rule.actual_ip >> 16) & 0xff,
                (rule.actual_ip >> 8) & 0xff,
                rule.actual_ip & 0xff,
                rule.actual_port,
            );
        }
    }

    // ---- license --------------------------------------------------------
    let lic_sec = elf.find("license").map(|i| elf.shdr(i).unwrap());
    let license = match lic_sec {
        Some(sh) => {
            let mut b = obj[sh.off..sh.off + sh.size].to_vec();
            while b.last() == Some(&0) {
                b.pop();
            }
            b.push(0);
            b
        }
        None => b"GPL\0".to_vec(),
    };

    // ---- programs: load + attach ---------------------------------------
    let mut loaded = Loaded { hooks: Vec::new(), hit_map_fd: hit_fd };
    let mut any = false;
    for sec_idx in 0..elf.shnum {
        let name = elf.section_name(sec_idx);
        let Some(sh) = elf.shdr(sec_idx) else { continue };
        if sh.ty != 1 {
            continue; // SHT_PROGBITS
        }
        let Some(hook) = prog_for(&name) else { continue };
        if !wanted.iter().any(|w| *w == hook.name.as_str()) {
            if verbose {
                println!("  skipping {} (not in wanted set)", name);
            }
            continue;
        }
        any = true;

        // instructions (location independent; relocs patch map fds into them)
        let mut insns = obj[sh.off..sh.off + sh.size].to_vec();

        // relocations: .rel<section>
        let rel_name = format!(".rel{}", name);
        if let Some(rel_idx) = elf.find(&rel_name) {
            let rel_sh = elf.shdr(rel_idx).unwrap();
            let _prog_sec = rel_sh.info;
            let syms = elf.symtab();
            for (r_off, r_info) in elf.relocs(rel_idx) {
                let sym = (r_info >> 32) as usize;
                let r_type = (r_info & 0xffffffff) as u32;
                if r_type != 1 || sym >= syms.len() {
                    continue; // R_BPF_64_64 only
                }
                let (nm, _) = &syms[sym];
                let Some(map_fd) = fd_of(nm) else { continue };
                let slot = (r_off as usize) / 8;
                // mark BPF_PSEUDO_MAP_FD (src_reg=1) on the first insn word,
                // pack the fd into its imm, zero the second word's imm.
                let b = &mut insns[slot * 8 + 1];
                *b = (*b & 0x0f) | 0x10;
                insns[slot * 8 + 4..slot * 8 + 8].copy_from_slice(&(map_fd as u32).to_le_bytes());
                insns[slot * 8 + 12..slot * 8 + 16].fill(0);
                if verbose {
                    println!("  reloc {} -> fd {} @ insn {}", nm, map_fd, slot);
                }
            }
        }

        // PROG_LOAD
        let fd = match bpf::bpf_prog_load(hook.prog_type, &insns, &license, hook.attach_type) {
            Ok(fd) => fd,
            Err(e) => {
                let log = bpf::last_log();
                eprintln!("--- verifier log ({} bytes) ---", log.len());
                eprintln!("{}", String::from_utf8_lossy(log));
                return Err(format!("prog_load {}: {}", name, bpf::err_str(e)));
            }
        };
        if verbose {
            println!("  program {}: loaded fd={} ({} insns)", name, fd, insns.len() / 8);
        }

        // BPF_PROG_ATTACH
        bpf::bpf_prog_attach(cgroup_dir_fd, fd, hook.attach_type)
            .map_err(|e| format!("attach {} to cgroup: {}", name, bpf::err_str(e)))?;
        println!("  attached {} to cgroup (attach {})", name, hook.attach_type);

        loaded.hooks.push(hook);
    }
    if !any {
        return fail("load_and_attach", "no wanted program sections found in object");
    }
    Ok(loaded)
}