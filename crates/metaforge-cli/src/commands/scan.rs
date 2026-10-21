use crate::args::{OutputFormat, ScanArgs};
use crate::commands::read_guarded_file;
use crate::{export, table};
use metaforge_core::{ContainerType, MetaForgeError, MetadataEntry, TagCategory};
use metaforge_parsers::{
    detect_container_type, parse_gif, parse_heic, parse_jpeg, parse_png, parse_webp,
};

pub fn execute_scan(args: &ScanArgs, format: OutputFormat) -> Result<(), MetaForgeError> {
    let path = &args.file;
    let bytes = read_guarded_file(path)?;
    let container = detect_container_type(&bytes, path)?;
    let file_str = path.to_string_lossy().to_string();

    let mut entries = Vec::new();

    entries.push(MetadataEntry::new(
        TagCategory::Forensics,
        None,
        "Container",
        "Container Format",
        container.display_name(),
    ));
    entries.push(MetadataEntry::new(
        TagCategory::Forensics,
        None,
        "FileSize",
        "File Size",
        format!("{} bytes ({:.2} KB)", bytes.len(), bytes.len() as f64 / 1024.0),
    ));

    match container {
        ContainerType::Jpeg => {
            let info = parse_jpeg(&bytes)?;
            push_dimensions(&mut entries, info.width, info.height);
            if let Some(c) = info.comment {
                entries.push(MetadataEntry::new(TagCategory::Text, None, "JPEGComment", "JPEG Comment", c));
            }
            append_exif_metadata(&mut entries, &info.metadata);
        }
        ContainerType::Png => {
            let info = parse_png(&bytes)?;
            if let Some(h) = info.header {
                push_dimensions(&mut entries, Some(h.width), Some(h.height));
                entries.push(MetadataEntry::new(
                    TagCategory::Tiff,
                    None,
                    "BitDepth",
                    "Bit Depth",
                    format!("{} bits", h.bit_depth),
                ));
            }
            for (key, val) in info.text_metadata {
                entries.push(MetadataEntry::new(
                    TagCategory::Text,
                    None,
                    format!("PNG:{}", key),
                    format!("PNG Text ({})", key),
                    val,
                ));
            }
            append_exif_metadata(&mut entries, &info.metadata);
        }
        ContainerType::Webp => {
            let info = parse_webp(&bytes)?;
            push_dimensions(&mut entries, info.width, info.height);
            append_exif_metadata(&mut entries, &info.metadata);
        }
        ContainerType::Gif => {
            let info = parse_gif(&bytes)?;
            push_dimensions(&mut entries, Some(info.width as u32), Some(info.height as u32));
            if let Some(c) = info.comment {
                entries.push(MetadataEntry::new(TagCategory::Text, None, "GIFComment", "GIF Comment", c));
            }
            append_exif_metadata(&mut entries, &info.metadata);
        }
        ContainerType::Heic => {
            let info = parse_heic(&bytes)?;
            push_dimensions(&mut entries, info.width, info.height);
            append_exif_metadata(&mut entries, &info.metadata);
        }
        ContainerType::Unknown => {}
    }

    if args.exif_only {
        entries.retain(|e| e.category == TagCategory::Exif);
    } else if args.gps_only {
        entries.retain(|e| e.category == TagCategory::Gps);
    }

    match format {
        OutputFormat::Table => {
            let rendered = table::render_metadata_table(&file_str, &entries);
            println!("{}", rendered);
        }
        OutputFormat::Json => {
            export::export_json(&file_str, &entries).map_err(MetaForgeError::Io)?;
        }
        OutputFormat::Jsonl => {
            export::export_jsonl(&file_str, &entries).map_err(MetaForgeError::Io)?;
        }
        OutputFormat::Csv => {
            export::export_csv(&file_str, &entries).map_err(MetaForgeError::Io)?;
        }
    }

    Ok(())
}

fn push_dimensions(entries: &mut Vec<MetadataEntry>, width: Option<u32>, height: Option<u32>) {
    if let (Some(w), Some(h)) = (width, height) {
        entries.push(MetadataEntry::new(
            TagCategory::Tiff,
            Some(0x0100),
            "ImageWidth",
            "Image Width",
            format!("{} px", w),
        ));
        entries.push(MetadataEntry::new(
            TagCategory::Tiff,
            Some(0x0101),
            "ImageHeight",
            "Image Height",
            format!("{} px", h),
        ));
    }
}

fn append_exif_metadata(entries: &mut Vec<MetadataEntry>, meta: &metaforge_parsers::ExifMetadata) {
    if let Some(ref make) = meta.camera_make {
        entries.push(MetadataEntry::new(TagCategory::Tiff, Some(0x010F), "Make", "Camera Make", make));
    }
    if let Some(ref model) = meta.camera_model {
        entries.push(MetadataEntry::new(TagCategory::Tiff, Some(0x0110), "Model", "Camera Model", model));
    }
    if let Some(ref software) = meta.software {
        entries.push(MetadataEntry::new(TagCategory::Tiff, Some(0x0131), "Software", "Software", software));
    }
    if let Some(ref dto) = meta.date_time_original {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0x9003), "DateTimeOriginal", "Date/Time Original", dto));
    }
    if let Some(iso) = meta.iso {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0x8827), "ISOSpeedRatings", "ISO Speed", iso.to_string()));
    }
    if let Some(f_num) = meta.f_number {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0x829D), "FNumber", "F-Number", format!("f/{:.1}", f_num)));
    }
    if let Some(ref exp) = meta.exposure_time {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0x829A), "ExposureTime", "Exposure Time", format!("{} s", exp)));
    }
    if let Some(focal) = meta.focal_length_mm {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0x920A), "FocalLength", "Focal Length", format!("{:.1} mm", focal)));
    }
    if let Some(ref lmake) = meta.lens_make {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0xA433), "LensMake", "Lens Make", lmake));
    }
    if let Some(ref lmodel) = meta.lens_model {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0xA434), "LensModel", "Lens Model", lmodel));
    }
    if let Some(ref bserial) = meta.body_serial_number {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0xA431), "BodySerialNumber", "Camera Serial", bserial));
    }
    if let Some(ref lserial) = meta.lens_serial_number {
        entries.push(MetadataEntry::new(TagCategory::Exif, Some(0xA435), "LensSerialNumber", "Lens Serial", lserial));
    }

    if let Some(ref gps) = meta.gps {
        if let Some(lat) = gps.latitude {
            entries.push(MetadataEntry::new(TagCategory::Gps, Some(0x0002), "GPSLatitude", "GPS Latitude", format!("{:.6}°", lat)));
        }
        if let Some(lon) = gps.longitude {
            entries.push(MetadataEntry::new(TagCategory::Gps, Some(0x0004), "GPSLongitude", "GPS Longitude", format!("{:.6}°", lon)));
        }
        if let Some(alt) = gps.altitude {
            entries.push(MetadataEntry::new(TagCategory::Gps, Some(0x0006), "GPSAltitude", "GPS Altitude", format!("{:.2} m", alt)));
        }
        if let Some(speed) = gps.speed {
            entries.push(MetadataEntry::new(TagCategory::Gps, Some(0x000D), "GPSSpeed", "GPS Speed", format!("{:.2}", speed)));
        }
        if let Some(track) = gps.track {
            entries.push(MetadataEntry::new(TagCategory::Gps, Some(0x000F), "GPSTrack", "GPS Track", format!("{:.2}°", track)));
        }
    }
}
