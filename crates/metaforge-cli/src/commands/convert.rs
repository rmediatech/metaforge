use crate::args::{ConvertArgs, OutputFormat};
use crate::commands::parse_resize_spec;
use metaforge_converter::{
    convert_media, convert_stream, AudioConvertOptions, AudioTargetFormat, ConvertReport,
    ImageConvertOptions, ImageTargetFormat, UnifiedConvertOptions, VideoConvertOptions,
    VideoTargetFormat,
};
use metaforge_core::MetaForgeError;
use std::fs;
use std::path::PathBuf;

pub fn print_convert_report(
    report: &ConvertReport,
    format: OutputFormat,
) -> Result<(), MetaForgeError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|e| MetaForgeError::Io(std::io::Error::other(e.to_string())))?;
            println!("{}", json);
        }
        _ => {
            println!(
                "\n🔄 Transcode Complete: {} ➔ {}",
                report.input_path, report.output_path
            );
            let mut t = comfy_table::Table::new();
            t.load_preset(comfy_table::presets::UTF8_FULL);
            t.set_header(vec!["Property", "Value"]);
            t.add_row(vec![
                "Input Size",
                &format!(
                    "{} bytes ({:.2} KB)",
                    report.input_bytes,
                    report.input_bytes as f64 / 1024.0
                ),
            ]);
            t.add_row(vec![
                "Output Size",
                &format!(
                    "{} bytes ({:.2} KB)",
                    report.output_bytes,
                    report.output_bytes as f64 / 1024.0
                ),
            ]);
            t.add_row(vec!["Target Format", &report.output_format]);
            t.add_row(vec!["Details", &report.details]);
            println!("{t}\n");
        }
    }
    Ok(())
}

pub fn execute_convert(args: &ConvertArgs, format: OutputFormat) -> Result<(), MetaForgeError> {
    if args.inputs.is_empty() {
        return Err(MetaForgeError::ConversionError {
            detail: "At least one input file must be specified".to_string(),
        });
    }

    let is_stdin = args.inputs.len() == 1 && args.inputs[0].as_os_str() == "-";
    let is_stdout = args.output.as_ref().is_some_and(|p| p.as_os_str() == "-");
    let resize = parse_resize_spec(&args.resize)?;

    if is_stdin || is_stdout {
        return execute_stream_convert(args, format, is_stdin, is_stdout, resize);
    }

    let pairs: Vec<(PathBuf, PathBuf)> = match (args.inputs.len(), &args.output, &args.target) {
        (2, None, None) => vec![(args.inputs[0].clone(), args.inputs[1].clone())],
        (1, Some(out), _) if !out.is_dir() => vec![(args.inputs[0].clone(), out.clone())],
        (1, None, Some(target)) => {
            let inp = &args.inputs[0];
            vec![(inp.clone(), inp.with_extension(target))]
        }
        (_, out_dir_opt, Some(target)) => {
            let dest_dir = out_dir_opt.clone().unwrap_or_else(|| PathBuf::from("."));
            if !dest_dir.exists() && !args.dry_run {
                fs::create_dir_all(&dest_dir)?;
            }
            args.inputs
                .iter()
                .map(|inp| {
                    let file_name = inp.file_stem().unwrap_or_default().to_string_lossy();
                    let out_name = format!("{}.{}", file_name, target);
                    (inp.clone(), dest_dir.join(out_name))
                })
                .collect()
        }
        _ => {
            return Err(MetaForgeError::ConversionError {
                detail: "Invalid conversion arguments. Usage: 'metaforge convert <input> <output>' or 'metaforge convert <input>... -t <target>'".to_string(),
            });
        }
    };

    for (inp, outp) in pairs {
        if args.dry_run {
            let in_meta = fs::metadata(&inp)?;
            println!("\n🔍 Dry-run: Conversion Pre-Flight Estimation");
            println!("  Input Path:   {}", inp.display());
            println!("  Output Path:  {}", outp.display());
            println!(
                "  Input Size:   {} bytes ({:.2} KB)",
                in_meta.len(),
                in_meta.len() as f64 / 1024.0
            );
            println!("  Operation:    Transcode to target container format\n");
            continue;
        }

        let target_ext = outp.extension().and_then(|s| s.to_str()).unwrap_or("png");
        let unified_opts = UnifiedConvertOptions {
            image: ImageConvertOptions {
                target_format: ImageTargetFormat::from_extension(target_ext)
                    .unwrap_or(ImageTargetFormat::Png),
                quality: Some(args.quality),
                resize,
                preserve_metadata: true,
                max_dimension: 16384,
            },
            audio: AudioConvertOptions {
                target_format: AudioTargetFormat::from_extension(target_ext)
                    .unwrap_or(AudioTargetFormat::Wav),
                target_sample_rate: args.rate,
                target_channels: args.channels,
                target_bits_per_sample: None,
                gain: args.gain,
                normalize: args.normalize,
            },
            video: VideoConvertOptions {
                target_format: VideoTargetFormat::from_extension(target_ext)
                    .unwrap_or(VideoTargetFormat::Mp4),
                quality: Some(args.quality),
                resize,
                fps: None,
                crf: Some(23),
                faststart: true,
                copy_streams: false,
            },
            dry_run: args.dry_run,
        };

        let report = convert_media(&inp, &outp, &unified_opts)?;
        print_convert_report(&report, format)?;
    }

    Ok(())
}

fn execute_stream_convert(
    args: &ConvertArgs,
    format: OutputFormat,
    is_stdin: bool,
    is_stdout: bool,
    resize: Option<(u32, u32)>,
) -> Result<(), MetaForgeError> {
    let target_fmt_str = if let Some(ref f) = args.target {
        f.clone()
    } else if let Some(ref out) = args.output {
        if out.as_os_str() != "-" {
            out.extension()
                .and_then(|s| s.to_str())
                .unwrap_or("wav")
                .to_string()
        } else {
            return Err(MetaForgeError::ConversionError {
                detail: "Explicit --target (e.g. -t wav, -t webp) is required when streaming to stdout '-'".to_string(),
            });
        }
    } else {
        return Err(MetaForgeError::ConversionError {
            detail: "Explicit --target (e.g. -t wav, -t webp) is required when streaming to stdout '-'".to_string(),
        });
    };

    let in_hint = if !is_stdin {
        args.inputs[0].extension().and_then(|s| s.to_str())
    } else {
        None
    };

    if args.dry_run {
        println!(
            "🔍 Dry-run: Streaming transcode from {} to {} planned (format: {})",
            if is_stdin {
                "<stdin>"
            } else {
                args.inputs[0].to_str().unwrap_or("input")
            },
            if is_stdout {
                "<stdout>"
            } else {
                args.output
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .unwrap_or("output")
            },
            target_fmt_str
        );
        return Ok(());
    }

    let img_opts = ImageConvertOptions {
        target_format: ImageTargetFormat::from_extension(&target_fmt_str)
            .unwrap_or(ImageTargetFormat::Png),
        quality: Some(args.quality),
        resize,
        preserve_metadata: true,
        max_dimension: 16384,
    };

    let audio_opts = AudioConvertOptions {
        target_format: AudioTargetFormat::from_extension(&target_fmt_str)
            .unwrap_or(AudioTargetFormat::Wav),
        target_sample_rate: args.rate,
        target_channels: args.channels,
        target_bits_per_sample: None,
        gain: args.gain,
        normalize: args.normalize,
    };

    let report = if is_stdin && is_stdout {
        convert_stream(
            std::io::stdin().lock(),
            std::io::stdout().lock(),
            in_hint,
            &target_fmt_str,
            &img_opts,
            &audio_opts,
        )?
    } else if is_stdin {
        let out_p = args.output.as_ref().unwrap();
        let out_file = fs::File::create(out_p)?;
        convert_stream(
            std::io::stdin().lock(),
            out_file,
            in_hint,
            &target_fmt_str,
            &img_opts,
            &audio_opts,
        )?
    } else {
        let in_file = fs::File::open(&args.inputs[0])?;
        convert_stream(
            in_file,
            std::io::stdout().lock(),
            in_hint,
            &target_fmt_str,
            &img_opts,
            &audio_opts,
        )?
    };

    if !is_stdout {
        print_convert_report(&report, format)?;
    }
    Ok(())
}
