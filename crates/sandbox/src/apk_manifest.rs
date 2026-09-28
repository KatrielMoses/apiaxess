//! Reads an APK's package name straight from its binary `AndroidManifest.xml`.
//!
//! The Android target needs the installed app's package the moment `adb install`
//! succeeds (to offer "Open app"), long before apktool-based intake has decoded
//! the manifest. This is a bounded reader of the compiled (AXML) manifest: it
//! walks the string pool and the first `<manifest>` start element and returns its
//! `package` attribute. Every read is bounds-checked; malformed input is an
//! error, never a panic.

use std::io::Read as _;
use std::path::Path;

/// Compiled manifests are small; refuse anything implausibly large.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = 0xFFFF_FFFF;
const TYPE_STRING: u8 = 0x03;

/// Returns the `package` declared by the APK's compiled manifest.
///
/// # Errors
///
/// Returns a human-readable reason when the APK cannot be opened, has no
/// manifest, or the manifest is malformed or declares no package.
pub fn package_name(apk: &Path) -> Result<String, String> {
    let file = std::fs::File::open(apk)
        .map_err(|error| format!("could not open {}: {error}", apk.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("not a readable APK: {error}"))?;
    let mut entry = archive
        .by_name("AndroidManifest.xml")
        .map_err(|_| "the APK has no AndroidManifest.xml".to_owned())?;
    if entry.size() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "AndroidManifest.xml is implausibly large ({} bytes)",
            entry.size()
        ));
    }
    let mut bytes = Vec::new();
    entry
        .by_ref()
        .take(MAX_MANIFEST_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read AndroidManifest.xml: {error}"))?;
    package_from_axml(&bytes)
}

/// Extracts the `<manifest package="…">` value from compiled binary XML.
///
/// # Errors
///
/// Returns why the bytes are not a compiled manifest with a package.
pub fn package_from_axml(bytes: &[u8]) -> Result<String, String> {
    if u16_at(bytes, 0)? != RES_XML_TYPE {
        return Err("AndroidManifest.xml is not compiled binary XML".to_owned());
    }
    let mut offset = usize::from(u16_at(bytes, 2)?);
    let mut strings: Option<Vec<String>> = None;
    while offset < bytes.len() {
        let chunk_type = u16_at(bytes, offset)?;
        let chunk_size = usize::try_from(u32_at(bytes, offset + 4)?)
            .map_err(|_| "chunk size overflows".to_owned())?;
        if chunk_size < 8
            || offset
                .checked_add(chunk_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err("AndroidManifest.xml has a malformed chunk".to_owned());
        }
        let chunk = &bytes[offset..offset + chunk_size];
        match chunk_type {
            RES_STRING_POOL_TYPE if strings.is_none() => strings = Some(string_pool(chunk)?),
            RES_XML_START_ELEMENT_TYPE => {
                let pool = strings
                    .as_deref()
                    .ok_or_else(|| "the manifest element precedes its string pool".to_owned())?;
                if let Some(package) = manifest_package(chunk, pool)? {
                    return Ok(package);
                }
                // The first element is always <manifest>; if it carried no
                // package there is no point scanning its children.
                return Err("the <manifest> element declares no package".to_owned());
            }
            _ => {}
        }
        offset += chunk_size;
    }
    Err("AndroidManifest.xml has no <manifest> element".to_owned())
}

/// Decodes every string of a `ResStringPool` chunk.
fn string_pool(chunk: &[u8]) -> Result<Vec<String>, String> {
    let count = usize::try_from(u32_at(chunk, 8)?).map_err(|_| "string count overflows")?;
    let flags = u32_at(chunk, 16)?;
    let strings_start =
        usize::try_from(u32_at(chunk, 20)?).map_err(|_| "string offset overflows")?;
    let header_size = usize::from(u16_at(chunk, 2)?);
    let utf8 = flags & UTF8_FLAG != 0;
    // Each string needs at least a 4-byte offset entry, which bounds `count`.
    if count > chunk.len() / 4 {
        return Err("string pool count exceeds its chunk".to_owned());
    }
    (0..count)
        .map(|index| {
            let relative = usize::try_from(u32_at(chunk, header_size + index * 4)?)
                .map_err(|_| "string offset overflows".to_owned())?;
            let start = strings_start
                .checked_add(relative)
                .ok_or_else(|| "string offset overflows".to_owned())?;
            if utf8 {
                utf8_string(chunk, start)
            } else {
                utf16_string(chunk, start)
            }
        })
        .collect()
}

fn utf8_string(chunk: &[u8], start: usize) -> Result<String, String> {
    // UTF-16 length (skipped), then UTF-8 byte length; each 1 or 2 bytes.
    let (_, after_chars) = utf8_length(chunk, start)?;
    let (length, data) = utf8_length(chunk, after_chars)?;
    let end = data
        .checked_add(length)
        .filter(|end| *end <= chunk.len())
        .ok_or_else(|| "string runs past its pool".to_owned())?;
    Ok(String::from_utf8_lossy(&chunk[data..end]).into_owned())
}

fn utf8_length(chunk: &[u8], at: usize) -> Result<(usize, usize), String> {
    let first = *chunk.get(at).ok_or("string length runs past its pool")?;
    if first & 0x80 == 0 {
        Ok((usize::from(first), at + 1))
    } else {
        let second = *chunk
            .get(at + 1)
            .ok_or("string length runs past its pool")?;
        Ok((
            (usize::from(first & 0x7F) << 8) | usize::from(second),
            at + 2,
        ))
    }
}

fn utf16_string(chunk: &[u8], start: usize) -> Result<String, String> {
    let first = u16_at(chunk, start)?;
    let (length, data) = if first & 0x8000 == 0 {
        (usize::from(first), start + 2)
    } else {
        let second = u16_at(chunk, start + 2)?;
        (
            (usize::from(first & 0x7FFF) << 16) | usize::from(second),
            start + 4,
        )
    };
    let end = length
        .checked_mul(2)
        .and_then(|bytes| data.checked_add(bytes))
        .filter(|end| *end <= chunk.len())
        .ok_or_else(|| "string runs past its pool".to_owned())?;
    let units: Vec<u16> = chunk[data..end]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Returns the `package` attribute when `chunk` is the `<manifest>` element.
fn manifest_package(chunk: &[u8], strings: &[String]) -> Result<Option<String>, String> {
    let header_size = usize::from(u16_at(chunk, 2)?);
    let name = u32_at(chunk, header_size + 4)?;
    if lookup(strings, name) != Some("manifest") {
        return Err("the first element is not <manifest>".to_owned());
    }
    let attribute_start = usize::from(u16_at(chunk, header_size + 8)?);
    let attribute_size = usize::from(u16_at(chunk, header_size + 10)?);
    let attribute_count = usize::from(u16_at(chunk, header_size + 12)?);
    if attribute_size < 20 {
        return Err("the <manifest> attributes are malformed".to_owned());
    }
    for index in 0..attribute_count {
        let at = header_size + attribute_start + index * attribute_size;
        if lookup(strings, u32_at(chunk, at + 4)?) != Some("package") {
            continue;
        }
        let raw = u32_at(chunk, at + 8)?;
        let data_type = *chunk
            .get(at + 15)
            .ok_or("attribute runs past its element")?;
        let data = u32_at(chunk, at + 16)?;
        let value = if raw != NO_INDEX {
            lookup(strings, raw)
        } else if data_type == TYPE_STRING {
            lookup(strings, data)
        } else {
            None
        };
        return Ok(value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned));
    }
    Ok(None)
}

fn lookup(strings: &[String], index: u32) -> Option<&str> {
    usize::try_from(index)
        .ok()
        .and_then(|index| strings.get(index))
        .map(String::as_str)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .ok_or_else(|| "AndroidManifest.xml is truncated".to_owned())
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
        .ok_or_else(|| "AndroidManifest.xml is truncated".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a string pool in UTF-8 or UTF-16 form.
    fn pool(strings: &[&str], utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(u32::try_from(data.len()).unwrap());
            if utf8 {
                let chars = u8::try_from(value.encode_utf16().count()).unwrap();
                let bytes = u8::try_from(value.len()).unwrap();
                data.extend([chars, bytes]);
                data.extend(value.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = value.encode_utf16().collect();
                data.extend(u16::try_from(units.len()).unwrap().to_le_bytes());
                for unit in units {
                    data.extend(unit.to_le_bytes());
                }
                data.extend([0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28usize;
        let strings_start = header + offsets.len() * 4;
        let size = strings_start + data.len();
        let mut chunk = Vec::new();
        chunk.extend(RES_STRING_POOL_TYPE.to_le_bytes());
        chunk.extend(u16::try_from(header).unwrap().to_le_bytes());
        chunk.extend(u32::try_from(size).unwrap().to_le_bytes());
        chunk.extend(u32::try_from(offsets.len()).unwrap().to_le_bytes());
        chunk.extend(0u32.to_le_bytes()); // styles
        chunk.extend((if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        chunk.extend(u32::try_from(strings_start).unwrap().to_le_bytes());
        chunk.extend(0u32.to_le_bytes()); // styles start
        for offset in offsets {
            chunk.extend(offset.to_le_bytes());
        }
        chunk.extend(data);
        chunk
    }

    /// Encodes a start element with `(name_index, raw_value_index)` attributes.
    fn element(name: u32, attributes: &[(u32, u32)]) -> Vec<u8> {
        let mut chunk = Vec::new();
        let size = 16 + 20 + attributes.len() * 20;
        chunk.extend(RES_XML_START_ELEMENT_TYPE.to_le_bytes());
        chunk.extend(16u16.to_le_bytes());
        chunk.extend(u32::try_from(size).unwrap().to_le_bytes());
        chunk.extend(1u32.to_le_bytes()); // line
        chunk.extend(NO_INDEX.to_le_bytes()); // comment
        chunk.extend(NO_INDEX.to_le_bytes()); // ns
        chunk.extend(name.to_le_bytes());
        chunk.extend(20u16.to_le_bytes()); // attribute start
        chunk.extend(20u16.to_le_bytes()); // attribute size
        chunk.extend(u16::try_from(attributes.len()).unwrap().to_le_bytes());
        chunk.extend([0u8; 6]); // id/class/style
        for (attribute, raw) in attributes {
            chunk.extend(NO_INDEX.to_le_bytes()); // ns
            chunk.extend(attribute.to_le_bytes());
            chunk.extend(raw.to_le_bytes());
            chunk.extend(8u16.to_le_bytes());
            chunk.push(0);
            chunk.push(TYPE_STRING);
            chunk.extend(raw.to_le_bytes());
        }
        chunk
    }

    fn document(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut bytes = Vec::new();
        bytes.extend(RES_XML_TYPE.to_le_bytes());
        bytes.extend(8u16.to_le_bytes());
        bytes.extend(u32::try_from(8 + body.len()).unwrap().to_le_bytes());
        bytes.extend(body);
        bytes
    }

    const STRINGS: &[&str] = &[
        "versionCode",
        "package",
        "manifest",
        "pro.mailaccess.reference",
    ];

    #[test]
    fn reads_the_package_from_a_utf16_pool() {
        let bytes = document(&[pool(STRINGS, false), element(2, &[(0, 3), (1, 3)])]);
        assert_eq!(
            package_from_axml(&bytes).as_deref(),
            Ok("pro.mailaccess.reference")
        );
    }

    #[test]
    fn reads_the_package_from_a_utf8_pool() {
        let bytes = document(&[pool(STRINGS, true), element(2, &[(1, 3)])]);
        assert_eq!(
            package_from_axml(&bytes).as_deref(),
            Ok("pro.mailaccess.reference")
        );
    }

    #[test]
    fn a_manifest_without_a_package_is_an_error() {
        let bytes = document(&[pool(STRINGS, false), element(2, &[(0, 3)])]);
        assert!(
            package_from_axml(&bytes)
                .unwrap_err()
                .contains("no package")
        );
    }

    #[test]
    fn plain_text_xml_is_rejected() {
        let error = package_from_axml(b"<manifest package=\"x\"/>").unwrap_err();
        assert!(error.contains("not compiled"), "{error}");
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        let bytes = document(&[pool(STRINGS, false), element(2, &[(1, 3)])]);
        for cut in [0, 3, 9, 20, 40, bytes.len() / 2, bytes.len() - 1] {
            assert!(package_from_axml(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    /// Real `aapt2` output, when the gitignored local APKs are present.
    #[test]
    fn reads_real_apks_when_present() {
        const TEST: &str = "sandbox::apk_manifest::reads_real_apks_when_present";
        let reference = apiaxess_test_fixtures::workspace_root()
            .join("fixtures/reference-target/artifacts/mailaccess-reference-debug.apk");
        if reference.is_file() {
            assert_eq!(
                package_name(&reference).as_deref(),
                Ok("pro.mailaccess.reference")
            );
        } else {
            apiaxess_test_fixtures::skip(
                TEST,
                format_args!(
                    "reference APK not built at {} (gitignored)",
                    reference.display()
                ),
            );
        }
        if let Some(capstone) = apiaxess_test_fixtures::capstone_apk(TEST, &[]) {
            assert_eq!(
                package_name(&capstone).as_deref(),
                Ok("com.nononsenseapps.feeder")
            );
        }
    }

    #[test]
    fn an_out_of_range_string_index_is_rejected() {
        let bytes = document(&[pool(STRINGS, false), element(2, &[(1, 99)])]);
        assert!(package_from_axml(&bytes).is_err());
    }
}
