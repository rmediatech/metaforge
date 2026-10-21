use crate::args::{BatchArgs, OutputFormat, ProbeArgs};
use crate::commands::parse_resize_spec;
use metaforge_converter::{
    execute_batch_convert, probe_media_file, AudioConvertOptions, AudioTargetFormat,
    BatchConvertOptions, ImageConvertOptions, ImageTargetFormat,
};
use metaforge_core::MetaForgeError;

pub fn execute_batch(args: &BatchArgs, format: OutputFormat) -> Result<(), MetaForgeError> {
    let extensions: Vec<String> = if let Some(ref e) = args.ext {
        e.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let resize = parse_resize_spec(&args.resize)?;

    let target_img_fmt = args
        .target
        .as_deref()
        .and_then(ImageTargetFormat::from_extension)
        .unwrap_or(ImageTargetFormat::Png);

    let batch_opts = BatchConvertOptions {
        input_dir: args.input.clone(),
        output_dir: args.output.clone(),
        extensions,
        target_format: args.target.clone().unwrap_or_default(),
        max_workers: args.workers,
        dry_run: args.dry_run,
        flatten: args.flatten,
        image_options: ImageConvertOptions {
            target_format: target_img_fmt,
            quality: Some(args.quality),
            resize,
            preserve_metadata: true,
            max_dimension: 16384,
        },
        audio_options: AudioConvertOptions {
            target_format: AudioTargetFormat::from_extension(
                args.target.as_deref().unwrap_or("wav"),
            )
            .unwrap_or(AudioTargetFormat::Wav),
            target_sample_rate: args.rate,
            target_channels: args.channels,
            target_bits_per_sample: None,
            gain: args.gain,
            normalize: args.normalize,
        },
    };

    let report = execute_batch_convert(&batch_opts)?;

    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|e| MetaForgeError::Io(std::io::Error::other(e.to_string())))?;
            println!("{}", json);
        }
        _ => {
            let title = if report.dry_run {
                "🔍 Batch Conversion Pre-Flight Plan (Dry Run)"
            } else {
                "🚀 Batch Conversion Completed"
            };
            println!("\n{}", title);
            let mut t = comfy_table::Table::new();
            t.load_preset(comfy_table::presets::UTF8_FULL);
            t.set_header(vec!["Batch Metric", "Value"]);
            t.add_row(vec!["Total Scanned", &report.total_scanned.to_string()]);
            t.add_row(vec!["Converted", &report.converted.to_string()]);
            t.add_row(vec!["Skipped", &report.skipped.to_string()]);
            t.add_row(vec!["Failed", &report.failed.to_string()]);
            t.add_row(vec![
                "Total Input Data",
                &format!(
                    "{} bytes ({:.2} MB)",
                    report.total_input_bytes,
                    report.total_input_bytes as f64 / 1_048_576.0
                ),
            ]);
            if !report.dry_run {
                t.add_row(vec![
                    "Total Output Data",
                    &format!(
                        "{} bytes ({:.2} MB)",
                        report.total_output_bytes,
                        report.total_output_bytes as f64 / 1_048_576.0
                    ),
                ]);
            }
            t.add_row(vec!["Elapsed Time", &format!("{} ms", report.elapsed_ms)]);
            println!("{t}\n");

            if report.failed > 0 {
                eprintln!("⚠️ Warning: {} items failed to convert.", report.failed);
            }
        }
    }

    Ok(())
}

pub fn execute_probe(args: &ProbeArgs, format: OutputFormat) -> Result<(), MetaForgeError> {
    let probe = probe_media_file(&args.file)?;

    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json = serde_json::to_string_pretty(&probe)
                .map_err(|e| MetaForgeError::Io(std::io::Error::other(e.to_string())))?;
            println!("{}", json);
        }
        _ => {
            println!("\n🔍 Media Container Probe: {}", probe.file_path);
            let mut t = comfy_table::Table::new();
            t.load_preset(comfy_table::presets::UTF8_FULL);
            t.set_header(vec!["Stream Property", "Value"]);
            t.add_row(vec!["Media Kind", &probe.media_kind]);
            t.add_row(vec!["Format / Container", &probe.format]);
            t.add_row(vec![
                "File Size",
                &format!(
                    "{} bytes ({:.2} KB)",
                    probe.size_bytes,
                    probe.size_bytes as f64 / 1024.0
                ),
            ]);
            if let Some((w, h)) = probe.dimensions {
                t.add_row(vec!["Dimensions", &format!("{} x {} px", w, h)]);
            }
            if let Some(dur) = probe.duration_seconds {
                t.add_row(vec!["Duration", &format!("{:.3} s", dur)]);
            }
            if probe.audio_tracks > 0 {
                t.add_row(vec!["Audio Tracks", &probe.audio_tracks.to_string()]);
            }
            if probe.video_tracks > 0 {
                t.add_row(vec!["Video Tracks", &probe.video_tracks.to_string()]);
            }
            if let Some(codec) = probe.codec_name {
                t.add_row(vec!["Codec Name", &codec]);
            }
            if let Some(rate) = probe.sample_rate {
                t.add_row(vec!["Sample Rate", &format!("{} Hz", rate)]);
            }
            if let Some(ch) = probe.channels {
                let desc = match ch {
                    1 => "Mono (1 channel)",
                    2 => "Stereo (2 channels)",
                    _ => "Multi-Channel",
                };
                t.add_row(vec!["Channels", desc]);
            }
            if let Some(bits) = probe.bits_per_sample {
                t.add_row(vec!["Bits per Sample", &format!("{}-bit", bits)]);
            }
            println!("{t}\n");
        }
    }
    Ok(())
}
