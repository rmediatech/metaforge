//! Sovereign Establishment Tool Parity Suite (`metaforge` >= `file` / `exiftool`)
//!
//! Asserts that `metaforge` container detection, structural chunk/segment inspection,
//! and metadata extraction match standard `file` and `exiftool` behavioral invariants
//! without Perl/C runtime dependencies or external cloud telemetry.

use metaforge_core::{crc32, ContainerType};
use metaforge_parsers::{detect_container_type, parse_gif, parse_jpeg, parse_png, parse_webp};
use std::path::Path;

fn make_png_chunk(chunk_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(payload);
    let mut crc_input = Vec::with_capacity(4 + payload.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(payload);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    out
}

#[test]
fn parity_file_magic_signature_detection_ignores_spoofed_extension() {
    // Like `file --mime-type`, magic bytes take precedence over spoofed file extensions
    let mut png_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let ihdr = [
        0, 0, 0, 64, // width = 64
        0, 0, 0, 32, // height = 32
        8, 6, 0, 0, 0, // 8-bit RGBA
    ];
    png_bytes.extend_from_slice(&make_png_chunk(b"IHDR", &ihdr));
    png_bytes.extend_from_slice(&make_png_chunk(b"IEND", &[]));

    let detected = detect_container_type(&png_bytes, Path::new("spoofed_document.jpg"))
        .expect("should detect PNG container despite .jpg extension");
    assert_eq!(detected, ContainerType::Png);
}

#[test]
fn parity_exiftool_png_ihdr_text_and_time_extraction() {
    let mut png_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let ihdr = [
        0, 0, 7, 0x80, // width = 1920
        0, 0, 4, 0x38, // height = 1080
        8, 2, 0, 0, 0,
    ];
    png_bytes.extend_from_slice(&make_png_chunk(b"IHDR", &ihdr));
    png_bytes.extend_from_slice(&make_png_chunk(b"tEXt", b"Software\0MetaForge Sovereign Engine"));
    png_bytes.extend_from_slice(&make_png_chunk(
        b"tIME",
        &[0x07, 0xEA, 10, 18, 12, 30, 45], // 2026-10-18 12:30:45
    ));
    png_bytes.extend_from_slice(&make_png_chunk(b"IEND", &[]));

    let info = parse_png(&png_bytes).expect("valid PNG structure");
    let hdr = info.header.expect("IHDR parsed");
    assert_eq!(hdr.width, 1920);
    assert_eq!(hdr.height, 1080);
    assert_eq!(hdr.bit_depth, 8);
    assert_eq!(
        info.text_metadata,
        vec![(
            "Software".to_string(),
            "MetaForge Sovereign Engine".to_string()
        )]
    );
    assert_eq!(
        info.last_modified.as_deref(),
        Some("2026-10-18 12:30:45")
    );
    assert!(info.chunks.iter().all(|c| c.crc_valid));
}

#[test]
fn parity_exiftool_jpeg_sof0_dimensions_and_com_extraction() {
    let mut jpeg = vec![0xFF, 0xD8]; // SOI
    // COM segment: "Sovereign Audit"
    let comment = b"Sovereign Audit";
    jpeg.extend_from_slice(&[0xFF, 0xFE]);
    jpeg.extend_from_slice(&((comment.len() + 2) as u16).to_be_bytes());
    jpeg.extend_from_slice(comment);
    // SOF0 segment: precision=8, height=720 (0x02D0), width=1280 (0x0500), components=3
    let sof0 = [8, 0x02, 0xD0, 0x05, 0x00, 3];
    jpeg.extend_from_slice(&[0xFF, 0xC0]);
    jpeg.extend_from_slice(&((sof0.len() + 2) as u16).to_be_bytes());
    jpeg.extend_from_slice(&sof0);
    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let info = parse_jpeg(&jpeg).expect("valid JPEG");
    assert_eq!(info.width, Some(1280));
    assert_eq!(info.height, Some(720));
    assert_eq!(info.comment.as_deref(), Some("Sovereign Audit"));
    assert_eq!(info.official_end_offset, jpeg.len());
}

#[test]
fn parity_file_gif89a_and_webp_vp8x_dimensions() {
    // GIF89a 320x240
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&320u16.to_le_bytes());
    gif.extend_from_slice(&240u16.to_le_bytes());
    gif.extend_from_slice(&[0x00, 0x00, 0x00, 0x3B]); // no GCT, trailer ';'

    let gif_info = parse_gif(&gif).expect("valid GIF89a");
    assert_eq!(gif_info.width, 320);
    assert_eq!(gif_info.height, 240);

    // WebP VP8X 800x600 (stored as 24-bit width-1, height-1)
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&22u32.to_le_bytes());
    webp.extend_from_slice(b"WEBP");
    webp.extend_from_slice(b"VP8X");
    webp.extend_from_slice(&10u32.to_le_bytes());
    webp.extend_from_slice(&[0, 0, 0, 0]); // flags
    let w_minus_1 = 799u32.to_le_bytes();
    let h_minus_1 = 599u32.to_le_bytes();
    webp.extend_from_slice(&w_minus_1[0..3]);
    webp.extend_from_slice(&h_minus_1[0..3]);

    let webp_info = parse_webp(&webp).expect("valid WebP VP8X");
    assert_eq!(webp_info.width, Some(800));
    assert_eq!(webp_info.height, Some(600));
}
