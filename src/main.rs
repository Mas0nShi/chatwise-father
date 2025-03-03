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
struct Asset {
    name: Vec<u8>,
    data: Vec<u8>,
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
    rdata_section: Option<SectionInfo>,
    binary_format: BinaryFormat,
}

impl BinaryPatcher {
    fn new(file: File) -> Result<Self> {
        let mmap = unsafe { Mmap::map(&file)? };
        let obj = object::File::parse(&*mmap)?;
        let binary_format = obj.format();

        println!("Detected binary format: {:?}", binary_format);

        if binary_format == BinaryFormat::MachO {
            unimplemented!();
        }

        // find .rdata or similar section
        let mut rdata_section = None;

        for section in obj.sections() {
            let section_name = section.name()?.to_string();
            let matched_section = match binary_format {
                BinaryFormat::Pe => {
                    section_name == ".rdata" && section.kind() == SectionKind::ReadOnlyData
                }
                // BinaryFormat::MachO => {
                //     section_name == "__const" &&
                //     section.kind() == SectionKind::Unknown
                // },
                _ => false,
            };

            // println!("section_name: {}, section_kind: {:?}", section_name, section.kind());

            if matched_section {
                rdata_section = Some(SectionInfo {
                    virtual_address: section.address(),
                    file_offset: section.file_range().unwrap().0,
                    size: section.size(),
                });

                // println!("Found target section: {}", section_name);
                // println!("  Virtual Address: 0x{:x}", section.address());
                // println!("  File Offset: 0x{:x}", section.file_range().unwrap().0);
                // println!("  Size: 0x{:x}", section.size());
                break;
            }
        }

        assert!(rdata_section.is_some(), "RDATA section not found");

        Ok(Self {
            mmap,
            rdata_section,
            binary_format,
        })
    }

    fn convert_rva_to_file_offset(&self, rva: u64) -> Result<u64> {
        let Some(ref section) = self.rdata_section else {
            return Err(anyhow::anyhow!("RDATA section not found"));
        };

        // check if rva is in the target section
        if rva >= section.virtual_address && rva < section.virtual_address + section.size {
            // calculate the offset in the section
            let section_offset = rva - section.virtual_address;
            // return file offset
            return Ok(section.file_offset + section_offset);
        }

        Err(anyhow::anyhow!("RVA is not in rdata section"))
    }

    fn heuristic_search_assets(&self) -> Result<Vec<Asset>> {
        // get start offset and scan length
        let (start_offset, scan_length) = match self.binary_format {
            BinaryFormat::Pe => {
                let Some(section) = self.rdata_section.as_ref() else {
                    return Err(anyhow::anyhow!("RDATA section not found"));
                };
                (section.file_offset as usize, section.size as usize)
            }
            BinaryFormat::MachO => {
                unimplemented!();
            }
            _ => panic!("Unsupported binary format"),
        };

        let end_offset = start_offset.saturating_add(scan_length);
        assert!(end_offset <= self.mmap.len(), "end_offset is out of range");

        // println!("Scanning from offset 0x{:x} to 0x{:x}", start_offset, end_offset);

        let mut assets = Vec::new();
        let mut offset = start_offset;
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
            data,
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
            .filter(|a| is_config_js(&a.name))
            .collect::<Vec<_>>();
        assert_eq!(config_assets.len(), 1, "found multi or no config.js file");
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

        println!(
            "Patched asset: {}",
            String::from_utf8_lossy(&asset.name)
        );

        Ok(modified_data)
    }

    fn process_asset_data(&self, asset: &Asset) -> Result<Vec<u8>> {
        // decompress content
        let mut decompressor = brotli::Decompressor::new(asset.data.as_slice(), asset.data.len());
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed)?;

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

    println!("Patching binary...");
    let modified_data = patcher.patch_config(assets)?;
    fs::write(&args.output, modified_data)?;
    println!("Patching completed. Output file: {}", args.output);

    Ok(())
}

fn is_config_js(name: &[u8]) -> bool {
    if let Ok(name_str) = std::str::from_utf8(name) {
        let re = Regex::new(r"config\.[^.]+\.js$").unwrap();
        re.is_match(name_str)
    } else {
        false
    }
}
