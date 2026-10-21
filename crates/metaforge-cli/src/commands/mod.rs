pub mod batch_probe;
pub mod convert;
pub mod forensics;
pub mod scan;

pub use batch_probe::{execute_batch, execute_probe};
pub use convert::execute_convert;
pub use forensics::{execute_audit, execute_comment, execute_dump, execute_sanitize};
pub use scan::execute_scan;

use metaforge_core::MetaForgeError;
use std::fs;
use std::path::Path;

pub const MAX_FILE_SIZE_BYTES: u64 = 256 * 1024 * 1024; // 256 MB guardrail

pub fn read_guarded_file(path: &Path) -> Result<Vec<u8>, MetaForgeError> {
    let metadata = fs::metadata(path).map_err(|_| {
        MetaForgeError::FileNotFound(path.to_string_lossy().to_string())
    })?;

    let size = metadata.len();
    if size == 0 {
        return Err(MetaForgeError::EmptyFile(path.to_string_lossy().to_string()));
    }
    if size > MAX_FILE_SIZE_BYTES {
        return Err(MetaForgeError::FileTooLarge {
            size,
            max_size: MAX_FILE_SIZE_BYTES,
        });
    }

    fs::read(path).map_err(MetaForgeError::Io)
}

pub fn parse_resize_spec(spec: &Option<String>) -> Result<Option<(u32, u32)>, MetaForgeError> {
    if let Some(ref r) = spec {
        let parts: Vec<&str> = r.split('x').collect();
        if parts.len() == 2 {
            let w: u32 = parts[0].trim().parse().map_err(|_| MetaForgeError::ConversionError {
                detail: format!("Invalid resize width: '{}'", parts[0]),
            })?;
            let h: u32 = parts[1].trim().parse().map_err(|_| MetaForgeError::ConversionError {
                detail: format!("Invalid resize height: '{}'", parts[1]),
            })?;
            Ok(Some((w, h)))
        } else {
            Err(MetaForgeError::ConversionError {
                detail: format!("Invalid resize format '{}'. Expected WxH (e.g. 800x600)", r),
            })
        }
    } else {
        Ok(None)
    }
}
