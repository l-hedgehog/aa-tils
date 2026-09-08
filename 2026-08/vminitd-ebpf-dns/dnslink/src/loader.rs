//! The attach-mode loader: aya parses the embedded .o, creates/pins maps,
//! populates cfg, loads each hook and attaches it to a cgroup.

use aya::{
    maps::{Array, IterableMap, MapData, PerCpuArray},
    programs::links::{FdLink, PinnedLink},
    programs::{loaded_programs, CgroupAttachMode, CgroupSockAddr},
    EbpfLoader, Pod, VerifierLogLevel,
};
use std::fmt;
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

/// One redirect rule (on-disk ABI: `<IIHH`, 12 bytes).
#[derive(Clone, Copy)]
pub struct Rule {
    pub requested_ip: u32,
    pub actual_ip: u32,
    pub requested_port: u16,
    pub actual_port: u16,
}
unsafe impl Pod for Rule {}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <-> {}",
            SocketAddrV4::new(
                Ipv4Addr::from_bits(u32::from_be(self.requested_ip)),
                u16::from_be(self.requested_port),
            ),
            SocketAddrV4::new(
                Ipv4Addr::from_bits(u32::from_be(self.actual_ip)),
                u16::from_be(self.actual_port),
            ),
        )
    }
}

/// Cgroup-sockaddr hooks as (name, display label, hit_cnt key); aya
/// derives the program/attach types from the section name.
pub const HOOKS: &[(&str, &str, u32)] = &[
    ("redirect_dns_query_connect", "connect4", 0),
    ("redirect_dns_query_sendmsg", "sendmsg4", 1),
    ("rewrite_dns_answer_recvmsg", "recvmsg4", 2),
];

pub struct Loaded {
    pub hooks: Vec<String>,
    pub hit_map: PerCpuArray<MapData, u64>,
}

/// Attach the hook programs in `obj` to `cgroup_dir`, write `rules` into
/// cfg_map, and return the hit_cnt map (consumed by `watch_hits`).
/// `pin_basedir` is
/// the bpffs dir under which links/maps are pinned (survive our exit/exec).
pub fn load_and_attach<P: AsRef<Path>>(
    obj: &[u8],
    cgroup_dir: &File,
    rules: &Vec<(u32, Rule)>,
    pin_basedir: P,
    verbose: bool,
) -> Result<Loaded, anyhow::Error> {
    // ---- pre-scan pinned links: recover program tags before reload -------
    // A pin entry means a pin file exists at `<pin_basedir>/<name>`;
    // Some(tag) = tag recovered, None = pin found but tag unrecoverable.
    // Scan loaded_programs() once into (id, tag) pairs (each call is a
    // full bpf_prog_get_next_id walk); lookups are a linear find over a
    // handful of entries.
    let mut id_to_tag: Vec<(u32, u64)> = Vec::new();
    for pi in loaded_programs().flatten() {
        id_to_tag.push((pi.id(), pi.tag()));
    }
    let mut pinned: Vec<(&str, Option<u64>)> = Vec::new();
    for (name, _, _) in HOOKS {
        let pin_path = pin_basedir.as_ref().join(name);
        match PinnedLink::from_pin(&pin_path) {
            Ok(pinned_link) => {
                let fd_link: FdLink = pinned_link.into();
                match fd_link.info().map(|li| li.program_id()) {
                    Ok(prog_id) => match id_to_tag.iter().find(|(id, _)| *id == prog_id) {
                        Some((_, tag)) => {
                            if verbose {
                                eprintln!("pinned at {} tag {:x}", pin_path.display(), tag);
                            }
                            pinned.push((name, Some(*tag)));
                        }
                        None => {
                            if verbose {
                                eprintln!(
                                    "pinned at {}: no loaded program with id {}; treating as stale",
                                    pin_path.display(),
                                    prog_id
                                );
                            }
                            pinned.push((name, None));
                        }
                    },
                    Err(e) => {
                        if verbose {
                            eprintln!(
                                "pinned at {}: link info failed: {}; treating as stale",
                                pin_path.display(),
                                e
                            );
                        }
                        pinned.push((name, None));
                    }
                }
            }
            Err(_) => {
                if verbose {
                    eprintln!("no {} program pinned in bpffs", name);
                }
            }
        }
    }

    // Explicit per-map pin paths for cfg_map/hit_cnt (these override the
    // default_map_pin_directory below, which stays as the fallback for any
    // other pinned-by-name map in the object). Same <basedir>/<name> location
    // the default would produce, so behaviour is unchanged — just pinned
    // explicitly.
    let cfg_pin_path = pin_basedir.as_ref().join("cfg_map");
    let hit_pin_path = pin_basedir.as_ref().join("hit_cnt");
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(&pin_basedir)
        .map_pin_path("cfg_map", cfg_pin_path)
        .map_pin_path("hit_cnt", hit_pin_path)
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load(obj)?;

    let mut cfg_map = Array::<_, Rule>::try_from(
        ebpf.take_map("cfg_map")
            .ok_or(anyhow::Error::msg("no cfg_map in object"))?,
    )?;
    if verbose {
        eprintln!("  map id {}", cfg_map.map().info().unwrap().id());
    }

    // ---- populate cfg_map ----------------------------------------------
    // Right after load, before any attach: a fresh program never runs
    // against stale rules.
    for (idx, rule) in rules {
        cfg_map.set(*idx, rule, 0)?;
        if verbose {
            println!("  cfg[{}]: {}", idx, rule);
        }
    }

    // ---- programs: load + attach ---------------------------------------
    let mut hooks = Vec::new();
    let mut found_hook = false;
    for (name, program) in ebpf.programs_mut() {
        if !HOOKS.iter().any(|(n, _, _)| *n == name) {
            continue;
        }
        found_hook = true;
        let pin_path = pin_basedir.as_ref().join(name);
        // Option<Option<u64>>: None = not pinned; Some(None) = pinned but tag
        // unrecoverable (stale); Some(Some(tag)) = pinned with recovered tag.
        let pinned_tag = pinned.iter().find(|(n, _)| *n == name).map(|(_, t)| *t);
        let cgroup_sock_addr: &mut CgroupSockAddr = program.try_into()?;
        cgroup_sock_addr.load()?;
        let program_info = cgroup_sock_addr.info()?;
        let new_tag = program_info.tag();
        if verbose {
            println!("  {:x} {}", new_tag, name);
        }
        let mut do_attach = true;
        match pinned_tag {
            Some(None) => {
                if verbose {
                    eprintln!(
                        "relinking {}: pinned tag unrecoverable, new tag {:x}",
                        name, new_tag
                    );
                }
            }
            Some(Some(old_tag)) => {
                if old_tag == new_tag {
                    if verbose {
                        eprintln!("tag match, keeping pinned link for {}", name);
                    }
                    do_attach = false;
                } else if verbose {
                    eprintln!("relinking {}: tag {:x} != new {:x}", name, old_tag, new_tag);
                }
            }
            None => {}
        }
        if do_attach {
            // Drop the stale pin first, else BPF_OBJ_PIN EEXIST would leave
            // the OLD program attached and the NEW one unpinned.
            let _ = std::fs::remove_file(&pin_path);
            // See https://github.com/aya-rs/aya/issues/1078 for bug in CgroupAttachMode
            let link_id = cgroup_sock_addr.attach(cgroup_dir, CgroupAttachMode::default())?;
            // Pin the link so the attachment survives our exit/exec (bpf_link fds
            // are closed on drop and FD_CLOEXEC at execve). Non-fatal: try_into
            // fails on <5.7 PROG_ATTACH links, but that path is durable already;
            // pin EEXIST just means "pinned by an earlier run".
            let fd_link: Result<FdLink, _> = cgroup_sock_addr.take_link(link_id)?.try_into();
            match fd_link {
                Ok(fd_link) => match fd_link.pin(&pin_path) {
                    Ok(_) => {
                        if verbose {
                            println!("  pinned link at {}", pin_path.display());
                        }
                    }
                    Err(e) => eprintln!(
                        "dnslink: pin link at {}: {}; hook not in effect",
                        pin_path.display(),
                        e
                    ),
                },
                Err(_) => {
                    if verbose {
                        println!(
                            "  {}: pre-5.7 PROG_ATTACH link, already durable; skipped pin",
                            name
                        );
                    }
                }
            }
        }
        hooks.push(name.to_string());
    }
    if !found_hook {
        return Err(anyhow::Error::msg(
            "load_and_attach: no hook programs found in object",
        ));
    }

    // Auto-reused across reloads via default_map_pin_directory +
    // LIBBPF_PIN_BY_NAME create-or-reuse, so take_map returns the pinned
    // instance.
    let hit_cnt = PerCpuArray::try_from(
        ebpf.take_map("hit_cnt")
            .ok_or(anyhow::Error::msg("no hit_cnt in object"))?,
    )?;
    let loaded = Loaded {
        hooks,
        hit_map: hit_cnt,
    };
    Ok(loaded)
}
