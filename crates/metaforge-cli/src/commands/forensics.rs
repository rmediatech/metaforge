use crate::args::{AuditArgs, CommentArgs, DumpArgs, OutputFormat, SanitizeArgs};
use crate::commands::read_guarded_file;
use crate::table::{self, scrub_terminal_poisoning};
use metaforge_core::{ContainerType, MetaForgeError};
use metaforge_forensics::{
    analyze_jpeg_steganography, calculate_shannon_entropy, detect_overlay, scan_embedded_payloads,
};
use metaforge_parsers::{
    detect_container_type, parse_gif, parse_heic, parse_jpeg, parse_png, parse_webp,
};
use metaforge_sanitize::{
    read_jpeg_comments, read_png_text, scrub_image, set_jpeg_comment, set_png_text,
    truncate_overlay,
};
use std::fs;

pub fn execute_audit(args: &AuditArgs, _format: OutputFormat) -> Result<(), MetaForgeError> {
    let path = &args.file;
    let bytes = read_guarded_file(path)?;
    let container = detect_container_type(&bytes, path)?;
    let file_str = path.to_string_lossy().to_string();

    let official_end_offset = match container {
        ContainerType::Jpeg => parse_jpeg(&bytes)?.official_end_offset,
        ContainerType::Png => parse_png(&bytes)?.official_end_offset,
        ContainerType::Webp => parse_webp(&bytes)?.official_end_offset,
        ContainerType::Gif => parse_gif(&bytes)?.official_end_offset,
        ContainerType::Heic => parse_heic(&bytes)?.official_end_offset,
        ContainerType::Unknown => bytes.len(),
    };

    let entropy = calculate_shannon_entropy(&bytes);
    let is_suspicious_entropy = entropy >= args.entropy_threshold;
    let overlay = detect_overlay(&bytes, official_end_offset);
    let payloads = scan_embedded_payloads(&bytes, official_end_offset);

    let stego = if container == ContainerType::Jpeg {
        Some(analyze_jpeg_steganography(&bytes))
    } else {
        None
    };

    let output = table::render_audit_table(
        &file_str,
        entropy,
        is_suspicious_entropy,
        &overlay,
        &payloads,
        stego.as_ref(),
    );
    println!("{}", output);

    Ok(())
}

pub fn execute_sanitize(args: &SanitizeArgs) -> Result<(), MetaForgeError> {
    let path = &args.file;
    let bytes = read_guarded_file(path)?;
    let original_size = bytes.len();

    let (cleaned_bytes, overlay_truncated, meta_stripped, bytes_removed) = if args.overlay_only {
        let (cleaned, truncated) = truncate_overlay(&bytes)?;
        let removed = original_size.saturating_sub(cleaned.len());
        (cleaned, truncated, false, removed)
    } else {
        let (cleaned, report) = scrub_image(&bytes)?;
        (
            cleaned,
            report.overlay_truncated,
            report.metadata_stripped,
            report.bytes_removed,
        )
    };

    let target_path = if args.inplace {
        path.clone()
    } else if let Some(ref out) = args.out {
        out.clone()
    } else {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("image");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("clean");
        let new_name = format!("{}.clean.{}", stem, ext);
        path.with_file_name(new_name)
    };

    fs::write(&target_path, &cleaned_bytes).map_err(MetaForgeError::Io)?;

    println!("\n✨ Sanitization Complete: {}", target_path.display());
    println!(" • Original Size:     {} bytes", original_size);
    println!(" • Scrubbed Size:     {} bytes", cleaned_bytes.len());
    println!(" • Space Saved:       {} bytes", bytes_removed);
    println!(
        " • Overlay Removed:   {}",
        if overlay_truncated { "YES" } else { "NO" }
    );
    println!(
        " • Metadata Stripped: {}\n",
        if meta_stripped { "YES" } else { "NO" }
    );

    Ok(())
}

pub fn execute_comment(args: &CommentArgs) -> Result<(), MetaForgeError> {
    let path = &args.file;
    let bytes = read_guarded_file(path)?;
    let container = detect_container_type(&bytes, path)?;

    if args.delete {
        let cleaned = match container {
            ContainerType::Jpeg => set_jpeg_comment(&bytes, "")?,
            ContainerType::Png => set_png_text(&bytes, &args.key, "")?,
            _ => {
                return Err(MetaForgeError::SanitizationError {
                    path: path.to_string_lossy().to_string(),
                    detail: "Comment editing is only supported for JPEG and PNG containers".to_string(),
                });
            }
        };
        let out_path = args.out.as_ref().unwrap_or(path);
        fs::write(out_path, cleaned).map_err(MetaForgeError::Io)?;
        println!("🗑️  Deleted comment from {}", out_path.display());
        return Ok(());
    }

    if let Some(ref text) = args.set {
        let updated = match container {
            ContainerType::Jpeg => set_jpeg_comment(&bytes, text)?,
            ContainerType::Png => set_png_text(&bytes, &args.key, text)?,
            _ => {
                return Err(MetaForgeError::SanitizationError {
                    path: path.to_string_lossy().to_string(),
                    detail: "Comment editing is only supported for JPEG and PNG containers".to_string(),
                });
            }
        };
        let out_path = args.out.as_ref().unwrap_or(path);
        fs::write(out_path, updated).map_err(MetaForgeError::Io)?;
        println!("✍️  Updated comment in {}", out_path.display());
        return Ok(());
    }

    match container {
        ContainerType::Jpeg => {
            let comments = read_jpeg_comments(&bytes)?;
            if comments.is_empty() {
                println!("No JPEG comments found in {}", path.display());
            } else {
                println!("\n📝 JPEG Comments in {}:", path.display());
                for (idx, c) in comments.iter().enumerate() {
                    println!("  [{}] {}", idx + 1, scrub_terminal_poisoning(c));
                }
                println!();
            }
        }
        ContainerType::Png => {
            let texts = read_png_text(&bytes)?;
            if texts.is_empty() {
                println!("No PNG text chunks found in {}", path.display());
            } else {
                println!("\n📝 PNG Text Chunks in {}:", path.display());
                for (k, v) in texts {
                    println!(
                        "  • {}: {}",
                        scrub_terminal_poisoning(&k),
                        scrub_terminal_poisoning(&v)
                    );
                }
                println!();
            }
        }
        _ => {
            println!("Comment reading not supported for container: {:?}", container);
        }
    }

    Ok(())
}

pub fn execute_dump(args: &DumpArgs) -> Result<(), MetaForgeError> {
    let path = &args.file;
    let bytes = read_guarded_file(path)?;
    let container = detect_container_type(&bytes, path)?;

    println!("\n🔍 Container Structure Dump: {}", path.display());
    println!("Container Type: {}\n", container.display_name());

    match container {
        ContainerType::Jpeg => {
            let info = parse_jpeg(&bytes)?;
            println!("Found {} segments:", info.segments.len());
            for seg in info.segments {
                println!(
                    "  [0x{:08X}] 0xFF{:02X} {:<24} (length: {} bytes)",
                    seg.offset, seg.marker, seg.name, seg.length
                );
            }
        }
        ContainerType::Png => {
            let info = parse_png(&bytes)?;
            println!("Found {} chunks:", info.chunks.len());
            for chunk in info.chunks {
                let crc_status = if chunk.crc_valid { "CRC OK" } else { "CRC INVALID" };
                println!(
                    "  [0x{:08X}] {:<6} length: {:<8} CRC: 0x{:08X} ({})",
                    chunk.offset, chunk.type_name, chunk.length, chunk.crc, crc_status
                );
            }
        }
        ContainerType::Webp => {
            let info = parse_webp(&bytes)?;
            println!("Found {} RIFF chunks:", info.chunks.len());
            for c in info.chunks {
                println!("  [0x{:08X}] {:<6} length: {} bytes", c.offset, c.tag, c.length);
            }
        }
        ContainerType::Gif => {
            let info = parse_gif(&bytes)?;
            println!("Found {} GIF blocks:", info.blocks.len());
            for b in info.blocks {
                println!("  [0x{:08X}] {:<24} length: {} bytes", b.offset, b.block_type, b.length);
            }
        }
        ContainerType::Heic => {
            let info = parse_heic(&bytes)?;
            println!("Found {} ISOBMFF boxes:", info.boxes.len());
            for b in info.boxes {
                println!("  [0x{:08X}] {:<8} length: {} bytes", b.offset, b.box_type, b.length);
            }
        }
        ContainerType::Unknown => {
            println!("Unknown container type.");
        }
    }
    println!();
    Ok(())
}
