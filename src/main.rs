use anyhow::Result;
use clap::Parser;
use memmap2::Mmap;
use object::{BinaryFormat, Object, ObjectSection, SectionKind};
use regex::Regex;
use std::fs::{self, File};
use std::io::{Read, Write};

const ASSET_HEADER_SIZE: usize = size_of::<AssetHeader>();

#[repr(C)]
#[derive(Debug)]
struct AssetHeader {
    name_ptr: u64,
    name_len: u64,
    data_ptr: u64,
    data_size: u64,
}

#[derive(Debug)]
struct AssetData {
    data: Vec<u8>,
}

impl AssetData {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    fn decompress(&self) -> Result<Vec<u8>> {
        let mut decompressor = brotli::Decompressor::new(self.data.as_slice(), self.data.len());
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    #[allow(unused)]
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug)]
struct Asset {
    name: Vec<u8>,
    data: AssetData,
    data_off: u64,
    data_size_off: u64,
}

#[derive(Debug)]
struct SectionInfo {
    virtual_address: u64,
    file_offset: u64,
    size: u64,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    output: String,
}

struct BinaryPatcher {
    mmap: Mmap,
    // !for Windows PE,
    // - .rdata section
    // !for Mach-O
    // - __DATA segment, __const section
    // - __DATA_CONST segment, __const section
    sections: Vec<SectionInfo>,
    binary_format: BinaryFormat,
}

impl BinaryPatcher {
    fn new(file: File) -> Result<Self> {
        let mmap = unsafe { Mmap::map(&file)? };
        let obj = object::File::parse(&*mmap)?;
        let binary_format = obj.format();

        println!("Binary: {:?}/{:?}", obj.architecture(), binary_format);

        // find .rdata or similar section
        let sections = match binary_format {
            BinaryFormat::Pe => obj
                .sections()
                .filter(|s| s.name() == Ok(".rdata") && s.kind() == SectionKind::ReadOnlyData)
                .map(|s| SectionInfo {
                    virtual_address: s.address(),
                    file_offset: s.file_range().unwrap().0,
                    size: s.size(),
                })
                .collect::<Vec<_>>(),
            BinaryFormat::MachO => {
                // fliter all sections with segment name,
                // seg name is __TEXT or __DATA_CONST
                // and section name is __const
                obj.sections()
                    .filter(|s| {
                        s.segment_name() == Ok(Some("__TEXT"))
                            || s.segment_name() == Ok(Some("__DATA_CONST"))
                    })
                    .filter(|s| s.name() == Ok("__const"))
                    .map(|s| SectionInfo {
                        virtual_address: s.address(),
                        file_offset: s.file_range().unwrap().0,
                        size: s.size(),
                    })
                    .collect::<Vec<_>>()
            }
            _ => unreachable!(),
        };

        Ok(Self {
            mmap,
            sections,
            binary_format,
        })
    }

    fn convert_rva_to_file_offset(&self, rva: u64) -> Result<u64> {
        // in mach-o, __TEXT,__const section inlcude assets content,
        match self.binary_format {
            BinaryFormat::MachO => {
                // *Q: only need low 48 bits of the pointer
                // *A: high 16 bits has another meaning in mach-o
                return Ok(rva & 0xFFFFFFFFFFFF);
            }
            BinaryFormat::Pe => {
                let Some(ref section) = self.sections.first() else {
                    return Err(anyhow::anyhow!("RDATA section not found"));
                };

                // check if rva is in the target section
                if rva >= section.virtual_address && rva < section.virtual_address + section.size {
                    return Ok(rva - section.virtual_address + section.file_offset);
                }
            }
            _ => unreachable!(),
        }

        Err(anyhow::anyhow!("RVA is not in rdata section"))
    }

    fn heuristic_search_assets(&self) -> Result<Vec<Asset>> {
        // get start offset and scan length
        let (scan_start, scan_length) = match self.binary_format {
            BinaryFormat::Pe => {
                let section = self.sections.first().expect("RDATA section not found");
                (section.file_offset as usize, section.size as usize)
            }
            BinaryFormat::MachO => {
                // search range always in __DATA_CONST,__const section
                let section = self
                    .sections
                    .last()
                    .expect("__DATA_CONST section not found");
                (section.file_offset as usize, section.size as usize)
            }
            _ => panic!("Unsupported binary format"),
        };

        let end_offset = scan_start.saturating_add(scan_length);
        assert!(end_offset <= self.mmap.len(), "end_offset is out of range");

        // println!("Scanning from offset 0x{:x} to 0x{:x}", start_offset, end_offset);

        let mut assets = Vec::new();
        let mut offset = scan_start;
        let mut scan_step = 8; // TODO: detect PE/Mach-O file format to determine pointer size
        while offset + ASSET_HEADER_SIZE <= end_offset {
            if let Ok(asset) = self.try_parse_asset_at(offset) {
                // println!("Found asset at offset 0x{:x}: {}", offset, String::from_utf8_lossy(&asset.name));
                assets.push(asset);
                scan_step = ASSET_HEADER_SIZE;
            }

            offset += scan_step;
        }

        // println!("Scan completed");
        Ok(assets)
    }

    fn try_parse_asset_at(&self, offset: usize) -> Result<Asset> {
        assert!(
            offset + ASSET_HEADER_SIZE <= self.mmap.len(),
            "offset is out of range"
        );

        let chunk = &self.mmap[offset..offset + ASSET_HEADER_SIZE];

        let header = unsafe { &*(chunk.as_ptr() as *const AssetHeader) };

        let name_off = self.convert_rva_to_file_offset(header.name_ptr)?;
        let data_off = self.convert_rva_to_file_offset(header.data_ptr)?;

        if !self.validate_asset_pointers(name_off, header.name_len, data_off, header.data_size) {
            return Err(anyhow::anyhow!("invalid asset pointers"));
        }

        let name = self.extract_name(name_off as usize, header.name_len as usize)?;
        let data = self.extract_data(data_off as usize, header.data_size as usize)?;

        Ok(Asset {
            name,
            data: AssetData::new(data),
            data_off,
            data_size_off: (offset + 24) as u64,
        })
    }

    fn validate_asset_pointers(
        &self,
        name_ptr: u64,
        name_len: u64,
        data_ptr: u64,
        data_size: u64,
    ) -> bool {
        // check length
        if name_len == 0 || name_len > 1024 || data_size == 0 || data_size > 10 * 1024 * 1024 {
            return false;
        }

        let name_offset = name_ptr as usize;
        let data_offset = data_ptr as usize;

        // check if pointers are in the file range
        if name_offset >= self.mmap.len()
            || name_offset.saturating_add(name_len as usize) > self.mmap.len()
            || data_offset >= self.mmap.len()
            || data_offset.saturating_add(data_size as usize) > self.mmap.len()
        {
            return false;
        }

        // check name format
        if self.mmap[name_offset] != b'/' {
            return false;
        }

        // check brotli decompression
        let mut decompressor = brotli::Decompressor::new(
            &self.mmap[data_offset..data_offset + data_size as usize],
            data_size as usize,
        );
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed).is_ok()
    }

    fn extract_name(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        let name = self.mmap[offset..offset + len].to_vec();
        // validate name
        if !name.iter().all(|&b| b.is_ascii()) {
            return Err(anyhow::anyhow!("invalid name"));
        }
        Ok(name)
    }

    fn extract_data(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        Ok(self.mmap[offset..offset + len].to_vec())
    }

    fn patch_config(&self, assets: Vec<Asset>) -> Result<Vec<u8>> {
        let mut modified_data = self.mmap.to_vec();

        let config_assets = assets
            .iter()
            .filter(|a| is_config_js(&a.name, &a.data))
            .collect::<Vec<_>>();

        if config_assets.len() != 1 {
            return Err(anyhow::anyhow!(
                "found {} config assets, expected 1",
                config_assets.len()
            ));
        }

        let asset = config_assets[0];

        let new_data = self.process_asset_data(asset)?;

        if new_data.len() > asset.data.len() {
            return Err(anyhow::anyhow!("patched data is larger than original data"));
        }

        // replace data content
        let start_offset = asset.data_off as usize;
        modified_data[start_offset..start_offset + new_data.len()].copy_from_slice(&new_data);
        // replace data size
        let data_size_offset = asset.data_size_off as usize;
        modified_data[data_size_offset..data_size_offset + 8]
            .copy_from_slice(&(new_data.len() as u64).to_le_bytes());

        println!("Patched asset: {}", String::from_utf8_lossy(&asset.name));

        Ok(modified_data)
    }

    fn process_asset_data(&self, asset: &Asset) -> Result<Vec<u8>> {
        // decompress content
        let decompressed = asset.data.decompress()?;

        // replace content
        let content = String::from_utf8_lossy(&decompressed);

        if !content.contains("chatwise.app") {
            return Err(anyhow::anyhow!("content does not contain chatwise.app"));
        }

        let content = content.replace("chatwise.app", "cw.mas0n.org");

        // shorten content (line 2 is source map url, ignore it)
        let Some(content) = content.split("\n").next() else {
            return Err(anyhow::anyhow!("failed to shorten content"));
        };

        // compress content
        let mut compressed = Vec::new();
        {
            let mut compressor =
                brotli::CompressorWriter::new(&mut compressed, content.len(), 9, 22);
            compressor.write_all(content.as_bytes())?;
        }

        Ok(compressed)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.input)?;

    let patcher = BinaryPatcher::new(file)?;

    println!("Scanning for assets...");
    let assets = patcher.heuristic_search_assets()?;
    println!("Scanning completed. Found {} assets", assets.len());

    if assets.is_empty() {
        return Err(anyhow::anyhow!("No assets found"));
    }

    // for asset in &assets {
    //     use std::path::Path;
    //     println!("asset: {:?}", String::from_utf8_lossy(&asset.name));
    //     // save asset to file
    //     let file_name = format!("assets{}", String::from_utf8_lossy(&asset.name));
    //     // ensure the directory exists
    //     let dir = Path::new(&file_name).parent().unwrap();
    //     fs::create_dir_all(dir)?;
    //     let mut file = File::create(file_name)?;
    //     // decompress data
    //     let mut decompressor = brotli::Decompressor::new(asset.data.as_slice(), asset.data.len());
    //     let mut decompressed = Vec::new();
    //     decompressor.read_to_end(&mut decompressed)?;
    //     file.write_all(&decompressed)?;
    // }

    println!("Patching binary...");
    let modified_data = patcher.patch_config(assets)?;
    fs::write(&args.output, modified_data)?;
    println!("Patching completed. Output file: {}", args.output);

    Ok(())
}

fn is_config_js(name: &[u8], data: &AssetData) -> bool {
    if let Ok(name_str) = std::str::from_utf8(name) {
        let re1 = Regex::new(r"config\.[^.]+\.js$").unwrap();

        // match '="https://chatwise.app";'
        let re2 = Regex::new(r#"="https://chatwise.app";"#).unwrap();
        re1.is_match(name_str)
            || re2.is_match(&String::from_utf8_lossy(&data.decompress().unwrap()))
    } else {
        false
    }
}
