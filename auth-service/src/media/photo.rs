//! Turn an untrusted uploaded image into a safe, small avatar.
//!
//! Every upload is decoded and re-encoded from raw pixels. That:
//! - strips ALL metadata, including EXIF GPS location — important when the
//!   uploader may be a child photographing themselves at home;
//! - guarantees we only ever serve a plain JPEG, never attacker-chosen bytes;
//! - bounds the size of what we store and serve (256×256, ~10–30 KB).
//!
//! Decoding is CPU- and memory-heavy, so it runs on the blocking pool under a
//! semaphore, with decoder limits that reject decompression bombs.

use std::io::Cursor;

use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits, imageops::FilterType};

/// Output edge length in pixels (square).
pub const AVATAR_SIZE: u32 = 256;
const JPEG_QUALITY: u8 = 85;
/// Largest accepted source dimension. A 12 MP phone photo is ~4000×3000.
const MAX_SOURCE_DIMENSION: u32 = 6000;
/// Decoder allocation cap per image.
const MAX_DECODE_ALLOC: u64 = 96 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PhotoError {
    #[error("send a JPEG, PNG or WebP image")]
    UnsupportedFormat,
    #[error("the image could not be read")]
    Unreadable,
    #[error("the image is too large (max {MAX_SOURCE_DIMENSION}×{MAX_SOURCE_DIMENSION} pixels)")]
    TooLarge,
    #[error("the image is too small (min 64×64 pixels)")]
    TooSmall,
}

/// Decode, auto-rotate, centre-crop to a square, resize, and re-encode as JPEG.
/// Blocking: call via `spawn_blocking`.
pub fn process_avatar(bytes: &[u8]) -> Result<Vec<u8>, PhotoError> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| PhotoError::Unreadable)?;
    match reader.format() {
        Some(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP) => {}
        _ => return Err(PhotoError::UnsupportedFormat),
    }

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIMENSION);
    limits.max_image_height = Some(MAX_SOURCE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);

    let mut decoder = reader.into_decoder().map_err(map_decode_err)?;
    // Phone cameras store rotation in EXIF; apply it before we throw EXIF away.
    let orientation = decoder.orientation().map_err(map_decode_err)?;
    let mut img = DynamicImage::from_decoder(decoder).map_err(map_decode_err)?;
    img.apply_orientation(orientation);

    if img.width() < 64 || img.height() < 64 {
        return Err(PhotoError::TooSmall);
    }

    let square = img.resize_to_fill(AVATAR_SIZE, AVATAR_SIZE, FilterType::Lanczos3);
    let rgb = DynamicImage::ImageRgb8(square.to_rgb8()); // JPEG has no alpha

    let mut out = Vec::with_capacity(32 * 1024);
    rgb.write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
        &mut out,
        JPEG_QUALITY,
    ))
    .map_err(|_| PhotoError::Unreadable)?;
    Ok(out)
}

fn map_decode_err(err: image::ImageError) -> PhotoError {
    match err {
        image::ImageError::Limits(_) => PhotoError::TooLarge,
        image::ImageError::Unsupported(_) => PhotoError::UnsupportedFormat,
        _ => PhotoError::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgba, RgbaImage};

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_pixel(w, h, Rgba([200, 80, 40, 255]));
        let mut out = Vec::new();
        DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn produces_square_jpeg() {
        let out = process_avatar(&png(800, 400)).unwrap();
        assert_eq!(&out[..3], &[0xFF, 0xD8, 0xFF], "JPEG magic");
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(
            (decoded.width(), decoded.height()),
            (AVATAR_SIZE, AVATAR_SIZE)
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(matches!(
            process_avatar(b"definitely not an image"),
            Err(PhotoError::UnsupportedFormat | PhotoError::Unreadable)
        ));
        assert!(matches!(
            process_avatar(&png(10, 10)),
            Err(PhotoError::TooSmall)
        ));
        assert!(matches!(
            process_avatar(&png(6001, 64)),
            Err(PhotoError::TooLarge)
        ));
    }
}
