use std::io::Cursor;

use image::codecs::jpeg::JpegDecoder;
use image::ImageDecoder;
use sketching::*;

use super::ImageValidationError;

const JPEG_MAGIC: [u8; 2] = [0xff, 0xd8];
const EOI_MAGIC: [u8; 2] = [0xff, 0xd9];
const SOS_MARKER: [u8; 2] = [0xff, 0xda];

/// Checks to see if it has a valid JPEG magic bytes header
pub fn check_jpg_header(contents: &[u8]) -> Result<(), ImageValidationError> {
    if !contents.starts_with(&JPEG_MAGIC) {
        return Err(ImageValidationError::InvalidImage(
            "Failed to parse JPEG file, invalid magic bytes".to_string(),
        ));
    }
    Ok(())
}

// It's public so we can use it in benchmarking
/// Check to see if JPG is affected by acropalypse issues, returns `Ok(true)` if it is
/// based on <https://github.com/lordofpipes/acropadetect/blob/main/src/detect.ts>
pub fn has_trailer(contents: &Vec<u8>) -> Result<bool, ImageValidationError> {
    // Guard the EOI scan below, which computes `buf.len() - EOI_MAGIC.len()`. Callers in
    // ImageValue::validate reach this only after check_jpg_header and a full decode, but this is
    // pub (see the benchmark note above) so it cannot rely on that: release builds have no
    // overflow checks, so a short buffer would wrap the limit to usize::MAX and turn the scan
    // into an effectively unbounded loop rather than a clean error. png_has_trailer guards
    // itself the same way.
    if contents.len() < JPEG_MAGIC.len() + EOI_MAGIC.len() {
        return Err(ImageValidationError::InvalidImage(format!(
            "JPEG file is too short to be valid, got {} bytes",
            contents.len()
        )));
    }

    let buf = contents.as_slice();

    let mut pos = JPEG_MAGIC.len();

    while pos < buf.len() && pos + 4 < buf.len() {
        // We assert pos and pos+4 are both in bounds during
        // while iteration.
        #[allow(clippy::indexing_slicing)]
        let marker = &buf[pos..pos + 2];
        pos += 2;

        // pos was shifted by 2, so this is relative to +4 from
        // where the loop started.
        #[allow(clippy::indexing_slicing)]
        let segment_size_bytes: &[u8] = &buf[pos..pos + 2];
        let segment_size = u16::from_be_bytes(segment_size_bytes.try_into().map_err(|_| {
            ImageValidationError::InvalidImage("JPEG segment size bytes were invalid!".to_string())
        })?);
        // we do not add 2 because the size prefix includes the size of the size prefix
        pos += segment_size as usize;

        if marker == SOS_MARKER {
            break;
        }
    }

    let mut eoi_index = 0;
    let mut eoi_index_found = false;
    trace!("buffer length: {}", buf.len());

    // iterate through the file looking for the EOI_MAGIC bytes

    let buf_limit = buf.len() - EOI_MAGIC.len();

    for i in pos..=buf_limit {
        if buf.get(i..(i + EOI_MAGIC.len())) == Some(&EOI_MAGIC) {
            eoi_index_found = true;
            eoi_index = i;
            break;
        }
    }

    if !eoi_index_found {
        Err(ImageValidationError::InvalidImage(
            "End of image magic bytes not found in JPEG".to_string(),
        ))
    } else if (eoi_index + 2) < buf.len() {
        // there's still bytes in the buffer after the EOI magic bytes
        debug!(
            "we're at pos: {} and buf len is {}, is not OK",
            eoi_index,
            buf.len()
        );
        Ok(true)
    } else {
        debug!(
            "we're at pos: {} and buf len is {}, is OK",
            eoi_index,
            buf.len()
        );
        Ok(false)
    }
}

pub fn validate_decoding(
    filename: &str,
    contents: &[u8],
    limits: image::Limits,
) -> Result<(), ImageValidationError> {
    let mut decoder = match JpegDecoder::new(Cursor::new(contents)) {
        Ok(val) => val,
        Err(err) => {
            return Err(ImageValidationError::InvalidImage(format!(
                "Failed to parse {filename} as JPG: {err:?}"
            )))
        }
    };

    match decoder.set_limits(limits) {
        Err(err) => {
            sketching::admin_warn!(
                "Image validation failed while validating {}: {:?}",
                filename,
                err
            );
            Err(ImageValidationError::ExceedsMaxDimensions)
        }
        Ok(_) => Ok(()),
    }
}

#[test]
fn test_jpg_has_trailer() {
    let file_contents = std::fs::read(format!(
        "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("Failed to read file");
    assert!(!has_trailer(&file_contents).expect("Failed to check for JPEG trailer"));

    // checking a known bad image
    let file_contents = std::fs::read(format!(
        "{}/src/valueset/image/test_images/windows11_3_cropped.jpg",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("Failed to read file");
    // let test_bytes = vec![0xff, 0xd8, 0xff, 0xda, 0xff, 0xd9];

    assert!(has_trailer(&file_contents).expect("Failed to check for JPEG trailer"));
}

#[test]
fn test_jpg_has_trailer_rejects_short_buffers() {
    // Anything shorter than the magic plus an EOI marker cannot be a JPEG, and must error rather
    // than underflow the EOI scan limit.
    for len in 0..(JPEG_MAGIC.len() + EOI_MAGIC.len()) {
        let contents = vec![0xff; len];
        assert!(
            has_trailer(&contents).is_err(),
            "{len}-byte buffer should be rejected as too short"
        );
    }

    // The shortest buffer the scan will accept: magic plus EOI, and no trailing bytes.
    let contents = vec![0xff, 0xd8, 0xff, 0xd9];
    assert!(!has_trailer(&contents).expect("magic + EOI should parse"));
}
