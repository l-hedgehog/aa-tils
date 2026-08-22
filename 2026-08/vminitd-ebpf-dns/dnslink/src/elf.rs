//! Minimal ELF64 parsing for clang-built eBPF objects: section headers,
//! section names, symtab + strtab, SHT_REL relocations. No libbpf, no BTF.

pub struct Shdr {
    pub name: usize,     // index into shstrtab
    pub ty: u32,
    pub _flags: u64,
    pub _addr: u64,
    pub off: usize,
    pub size: usize,
    pub link: usize,     // index of associated section (e.g. symtab for SHT_REL)
    pub info: usize,     // e.g. section targeted by relocs
    pub addralign: u64,
    pub entsize: usize,
}

pub struct Sym {
    pub name: usize,     // index into linked strtab
    pub info: u8,
    pub shndx: i32,
    pub value: u64,
    pub size: u64,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub shoff: usize,
    pub shentsize: usize,
    pub shnum: usize,
    pub shstrndx: usize,
}

impl<'a> Elf<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        let hdr = data;
        if &hdr[0..4] != b"\x7fELF" {
            return None;
        }
        let e_machine = u16::from_le_bytes([hdr[18], hdr[19]]);
        if e_machine != 247 {
            // EM_BPF
            return None;
        }
        let shoff = u64::from_le_bytes(hdr[40..48].try_into().unwrap()) as usize;
        let shentsize = u16::from_le_bytes([hdr[58], hdr[59]]) as usize;
        let shnum = u16::from_le_bytes([hdr[60], hdr[61]]) as usize;
        let shstrndx = u16::from_le_bytes([hdr[62], hdr[63]]) as usize;
        if shnum == 0 || shentsize < 64 {
            return None;
        }
        Some(Self {
            data,
            shoff,
            shentsize,
            shnum,
            shstrndx,
        })
    }

    pub fn shdr(&self, i: usize) -> Option<Shdr> {
        if i >= self.shnum {
            return None;
        }
        let off = self.shoff + i * self.shentsize;
        let s = &self.data[off..off + self.shentsize];
        Some(Shdr {
            name: u32::from_le_bytes(s[0..4].try_into().unwrap()) as usize,
            ty: u32::from_le_bytes(s[4..8].try_into().unwrap()),
            _flags: u64::from_le_bytes(s[8..16].try_into().unwrap()),
            _addr: u64::from_le_bytes(s[16..24].try_into().unwrap()),
            off: u64::from_le_bytes(s[24..32].try_into().unwrap()) as usize,
            size: u64::from_le_bytes(s[32..40].try_into().unwrap()) as usize,
            link: u32::from_le_bytes(s[40..44].try_into().unwrap()) as usize,
            info: u32::from_le_bytes(s[44..48].try_into().unwrap()) as usize,
            addralign: u64::from_le_bytes(s[48..56].try_into().unwrap()),
            entsize: u64::from_le_bytes(s[56..64].try_into().unwrap()) as usize,
        })
    }

    /// Section name (bytes up to the next NUL in the shstrtab).
    fn section_name_raw(&self, i: usize) -> Option<&'a [u8]> {
        let sh = self.shdr(i)?;
        let tab = self.shdr(self.shstrndx)?;
        let base = tab.off;
        if base + sh.name >= self.data.len() {
            return None;
        }
        let mut end = base + sh.name;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        Some(&self.data[base + sh.name..end])
    }

    pub fn section_name(&self, i: usize) -> String {
        self.section_name_raw(i)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    /// Byte string at `off` within the strtab section `strtab_idx`.
    fn str_raw(&self, strtab_idx: usize, off: usize) -> Option<&'a [u8]> {
        let sh = self.shdr(strtab_idx)?;
        if off >= sh.size {
            return None;
        }
        let mut end = sh.off + off;
        let max = sh.off + sh.size;
        while end < max && self.data[end] != 0 {
            end += 1;
        }
        Some(&self.data[sh.off + off..end])
    }

    /// Symbol table as a Vec of (name, Sym).
    pub fn symtab(&self) -> Vec<(String, Sym)> {
        let mut out = Vec::new();
        for tab in 0..self.shnum {
            let Some(sh) = self.shdr(tab) else { continue };
            if sh.ty != 2 {
                continue; // SHT_SYMTAB
            }
            let strtab = sh.link;
            let stride = sh.entsize.max(24);
            let n = sh.size / stride;
            for k in 0..n {
                let off = sh.off + k * stride;
                if off + 24 > self.data.len() {
                    break;
                }
                let d = &self.data[off..off + 24];
                let name_off = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
                let info = d[4];
                let shndx = i16::from_le_bytes([d[6], d[7]]) as i32;
                let value = u64::from_le_bytes(d[8..16].try_into().unwrap());
                let size = u64::from_le_bytes(d[16..24].try_into().unwrap());
                let nm = self
                    .str_raw(strtab, name_off)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                out.push((nm, Sym { name: name_off, info, shndx, value, size }));
            }
            break; // first SHT_SYMTAB is enough
        }
        out
    }

    /// Find a section index by name.
    pub fn find(&self, name: &str) -> Option<usize> {
        (0..self.shnum).find(|&i| self.section_name(i) == name)
    }

    /// Relocation entries for section `sec_idx` (SHT_REL: r_offset + r_info).
    pub fn relocs(&self, rel_sec: usize) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let sh = match self.shdr(rel_sec) {
            Some(s) => s,
            None => return out,
        };
        let stride = sh.entsize.max(16);
        let n = sh.size / stride;
        for k in 0..n {
            let off = sh.off + k * stride;
            if off + 16 > self.data.len() {
                break;
            }
            let r_off = u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap());
            let r_info = u64::from_le_bytes(self.data[off + 8..off + 16].try_into().unwrap());
            out.push((r_off, r_info));
        }
        out
    }
}