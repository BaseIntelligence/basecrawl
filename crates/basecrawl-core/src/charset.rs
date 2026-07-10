//! Declared-charset detection and transcoding for textual response bodies.
//!
//! HTTP `Content-Type` takes precedence over an HTML `<meta charset>` declaration. The selected
//! source encoding is decoded through `encoding_rs`, so every text surface passed to the HTML,
//! markdown, links, and metadata producers is valid UTF-8.

use encoding_rs::{Encoding, UTF_8};

use crate::metadata;

const META_SCAN_LIMIT: usize = 8 * 1024;

/// Decode a textual response body to valid UTF-8.
///
/// A supported charset declared in the HTTP `Content-Type` header is authoritative. For HTML
/// without a header declaration, an ASCII-compatible `<meta charset>` or
/// `<meta http-equiv="content-type">` declaration is used. UTF-8 is the fallback when a source
/// does not declare a supported encoding.
pub fn decode_body(body: &[u8], content_type: Option<&str>, is_html: bool) -> String {
    let declared = content_type
        .and_then(metadata::charset_from_content_type)
        .or_else(|| is_html.then(|| charset_from_meta_bytes(body)).flatten());
    let encoding = declared
        .as_deref()
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(UTF_8);
    let (decoded, _, _) = encoding.decode(body);
    decoded.into_owned()
}

/// Find an HTML charset declaration without attempting to decode the whole body first.
///
/// Charset declarations in HTML are ASCII-compatible. This intentionally tokenizes only the
/// ASCII-compatible prefix instead of searching for a raw `"<meta"` substring: comments,
/// raw-text elements, template contents, malformed markup, and content after the effective head
/// boundary cannot declare a codec.
fn charset_from_meta_bytes(body: &[u8]) -> Option<String> {
    let input = &body[..body.len().min(META_SCAN_LIMIT)];
    let mut offset = 0;
    let mut accepts_metadata = true;
    let mut template_depth = 0usize;
    let mut raw_text: Option<&[u8]> = None;

    while offset < input.len() {
        if let Some(raw_name) = raw_text {
            if ascii_eq_ignore_case(raw_name, b"plaintext") {
                break;
            }

            if input[offset] != b'<' {
                offset += 1;
                continue;
            }

            match parse_markup(input, offset) {
                Markup::End { name, next } if ascii_eq_ignore_case(name, raw_name) => {
                    raw_text = None;
                    offset = next;
                }
                Markup::Incomplete => break,
                markup => offset = markup.next(),
            }
            continue;
        }

        if input[offset] != b'<' {
            // In the initial/in-head insertion mode, non-whitespace text begins the effective body.
            // Non-ASCII bytes are inert so legacy payload bytes cannot manufacture parser state.
            if template_depth == 0
                && input[offset].is_ascii()
                && !input[offset].is_ascii_whitespace()
            {
                accepts_metadata = false;
            }
            offset += 1;
            continue;
        }

        match parse_markup(input, offset) {
            Markup::Start {
                name,
                attributes,
                next,
            } => {
                if ascii_eq_ignore_case(name, b"template") {
                    template_depth += 1;
                }

                if accepts_metadata && template_depth == 0 && ascii_eq_ignore_case(name, b"meta") {
                    if let Some(charset) = charset_from_meta_attributes(attributes) {
                        return Some(charset);
                    }
                }

                if raw_text_element(name) {
                    raw_text = Some(name);
                }
                if template_depth == 0 && !head_context_element(name) {
                    accepts_metadata = false;
                }
                offset = next;
            }
            Markup::End { name, next } => {
                if ascii_eq_ignore_case(name, b"template") {
                    template_depth = template_depth.saturating_sub(1);
                }
                if template_depth == 0
                    && (ascii_eq_ignore_case(name, b"head") || ascii_eq_ignore_case(name, b"body"))
                {
                    accepts_metadata = false;
                }
                offset = next;
            }
            Markup::Other { next } => offset = next,
            Markup::Incomplete => break,
        }
    }
    None
}

/// A minimized byte-safe HTML tokenizer. It recognizes the markup relevant to the encoding
/// prescan and returns `Incomplete` rather than attempting recovery across the scan limit.
enum Markup<'a> {
    Start {
        name: &'a [u8],
        attributes: &'a [u8],
        next: usize,
    },
    End {
        name: &'a [u8],
        next: usize,
    },
    Other {
        next: usize,
    },
    Incomplete,
}

impl Markup<'_> {
    fn next(&self) -> usize {
        match self {
            Self::Start { next, .. } | Self::End { next, .. } | Self::Other { next } => *next,
            Self::Incomplete => unreachable!("incomplete markup has no next offset"),
        }
    }
}

fn parse_markup(input: &[u8], start: usize) -> Markup<'_> {
    debug_assert_eq!(input.get(start), Some(&b'<'));

    if input[start..].starts_with(b"<!--") {
        return input[start + 4..]
            .windows(3)
            .position(|window| window == b"-->")
            .map(|position| Markup::Other {
                next: start + 4 + position + 3,
            })
            .unwrap_or(Markup::Incomplete);
    }

    let Some(&first) = input.get(start + 1) else {
        return Markup::Incomplete;
    };
    if matches!(first, b'!' | b'?') {
        return tag_end(input, start + 2)
            .map(|end| Markup::Other { next: end + 1 })
            .unwrap_or(Markup::Incomplete);
    }

    let (is_end, name_start) = if first == b'/' {
        (true, start + 2)
    } else {
        (false, start + 1)
    };
    let Some(&name_first) = input.get(name_start) else {
        return Markup::Incomplete;
    };
    if !name_first.is_ascii_alphabetic() {
        return tag_end(input, name_start)
            .map(|end| Markup::Other { next: end + 1 })
            .unwrap_or(Markup::Incomplete);
    }

    let mut name_end = name_start + 1;
    while input
        .get(name_end)
        .is_some_and(|byte| is_tag_name_byte(*byte))
    {
        name_end += 1;
    }
    let Some(&delimiter) = input.get(name_end) else {
        return Markup::Incomplete;
    };
    if !matches!(
        delimiter,
        b'>' | b'/' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' '
    ) {
        return tag_end(input, name_end)
            .map(|end| Markup::Other { next: end + 1 })
            .unwrap_or(Markup::Incomplete);
    }

    let Some(end) = tag_end(input, name_end) else {
        return Markup::Incomplete;
    };
    let name = &input[name_start..name_end];
    if is_end {
        if input[name_end..end]
            .iter()
            .all(|byte| byte.is_ascii_whitespace())
        {
            Markup::End {
                name,
                next: end + 1,
            }
        } else {
            Markup::Other { next: end + 1 }
        }
    } else {
        Markup::Start {
            name,
            attributes: &input[name_end..end],
            next: end + 1,
        }
    }
}

fn tag_end(input: &[u8], mut index: usize) -> Option<usize> {
    let mut quote = None;
    while let Some(&byte) = input.get(index) {
        if let Some(expected_quote) = quote {
            if byte == expected_quote {
                quote = None;
            }
        } else {
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'>' => return Some(index),
                // A new tag opener cannot appear in a genuine start tag. Treat it as malformed
                // rather than allowing a pseudo-tag to consume later markup and select a codec.
                b'<' => return None,
                _ => {}
            }
        }
        index += 1;
    }
    None
}

fn is_tag_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':')
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn raw_text_element(name: &[u8]) -> bool {
    [
        b"script".as_slice(),
        b"style",
        b"textarea",
        b"title",
        b"xmp",
        b"iframe",
        b"noembed",
        b"noframes",
        b"noscript",
        b"plaintext",
    ]
    .iter()
    .any(|candidate| ascii_eq_ignore_case(name, candidate))
}

fn head_context_element(name: &[u8]) -> bool {
    [
        b"html".as_slice(),
        b"head",
        b"base",
        b"basefont",
        b"bgsound",
        b"link",
        b"meta",
        b"title",
        b"noframes",
        b"style",
        b"template",
        b"script",
        b"noscript",
    ]
    .iter()
    .any(|candidate| ascii_eq_ignore_case(name, candidate))
}

/// Parse the simple ASCII attributes used by HTML charset declarations.
fn charset_from_meta_attributes(attributes: &[u8]) -> Option<String> {
    let mut charset = None;
    let mut content = None;
    let mut is_content_type = false;
    let mut index = 0;

    while index < attributes.len() {
        while index < attributes.len()
            && (attributes[index].is_ascii_whitespace() || attributes[index] == b'/')
        {
            index += 1;
        }
        let name_start = index;
        while index < attributes.len()
            && !attributes[index].is_ascii_whitespace()
            && !matches!(attributes[index], b'=' | b'/' | b'>' | b'\'' | b'"')
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = &attributes[name_start..index];
        while index < attributes.len() && attributes[index].is_ascii_whitespace() {
            index += 1;
        }

        let value = if attributes.get(index) != Some(&b'=') {
            &[][..]
        } else {
            index += 1;
            while index < attributes.len() && attributes[index].is_ascii_whitespace() {
                index += 1;
            }
            match attributes.get(index) {
                Some(b'"') | Some(b'\'') => {
                    let quote = attributes[index];
                    index += 1;
                    let value_start = index;
                    while index < attributes.len() && attributes[index] != quote {
                        index += 1;
                    }
                    let value = &attributes[value_start..index];
                    if index < attributes.len() {
                        index += 1;
                    }
                    value
                }
                _ => {
                    let value_start = index;
                    while index < attributes.len()
                        && !attributes[index].is_ascii_whitespace()
                        && !matches!(attributes[index], b'/')
                    {
                        index += 1;
                    }
                    &attributes[value_start..index]
                }
            }
        };
        if charset.is_none() && ascii_eq_ignore_case(name, b"charset") && !value.is_empty() {
            charset = ascii_string(value);
        } else if ascii_eq_ignore_case(name, b"http-equiv")
            && ascii_eq_ignore_case(value, b"content-type")
        {
            is_content_type = true;
        } else if content.is_none() && ascii_eq_ignore_case(name, b"content") {
            content = ascii_string(value);
        }
    }

    charset.or_else(|| {
        is_content_type
            .then(|| content.and_then(|value| metadata::charset_from_content_type(&value)))
            .flatten()
    })
}

fn ascii_string(bytes: &[u8]) -> Option<String> {
    bytes
        .iter()
        .all(u8::is_ascii)
        .then(|| String::from_utf8_lossy(bytes).to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{decode_body, META_SCAN_LIMIT};

    fn assert_falls_back_to_utf8(body: &[u8]) {
        let decoded = decode_body(body, Some("text/html"), true);
        assert!(
            !decoded.contains("café"),
            "a non-head declaration selected ISO-8859-1: {decoded:?}"
        );
        assert!(
            decoded.contains('\u{fffd}'),
            "invalid UTF-8 should use the deterministic UTF-8 fallback: {decoded:?}"
        );
    }

    #[test]
    fn decodes_header_declared_latin1() {
        let decoded = decode_body(b"caf\xe9", Some("text/plain; charset=ISO-8859-1"), false);
        assert_eq!(decoded, "café");
    }

    #[test]
    fn decodes_meta_declared_shift_jis() {
        let mut body = b"<meta charset=Shift_JIS>".to_vec();
        body.extend([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
        assert_eq!(
            decode_body(&body, Some("text/html"), true),
            "<meta charset=Shift_JIS>日本語"
        );
    }

    #[test]
    fn header_charset_takes_precedence_over_meta() {
        let body = b"<meta charset=Shift_JIS>caf\xe9";
        assert_eq!(
            decode_body(body, Some("text/html; charset=iso-8859-1"), true),
            "<meta charset=Shift_JIS>café"
        );
    }

    #[test]
    fn recognizes_http_equiv_meta_charset() {
        let mut body =
            b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=Shift_JIS\">".to_vec();
        body.extend([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
        assert!(
            decode_body(&body, Some("text/html"), true).contains("日本語"),
            "http-equiv charset declaration should govern decoding"
        );
    }

    #[test]
    fn ignores_meta_like_text_in_comments_and_raw_text_elements() {
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head>\
              <!-- <meta charset=iso-8859-1> -->\
              <script>const declaration = '<meta charset=iso-8859-1>';</script>\
              <style>.declaration::after { content: '<meta charset=iso-8859-1>'; }</style>\
              <noscript><meta charset=iso-8859-1></noscript>\
              <textarea><meta charset=iso-8859-1></textarea>\
              <title><meta charset=iso-8859-1></title>\
              <body>caf\xe9</body></html>",
        );
    }

    #[test]
    fn ignores_meta_inside_template_content() {
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head>\
              <template><meta charset=iso-8859-1></template>\
              <body>caf\xe9</body></html>",
        );
    }

    #[test]
    fn recognizes_genuine_head_meta_after_ignored_content() {
        let decoded = decode_body(
            b"<!doctype html><html><head>\
              <!-- <meta charset=shift_jis> -->\
              <script>const declaration = '<meta charset=utf-8>';</script>\
              <meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-1\">\
              </head><body>caf\xe9</body></html>",
            Some("text/html"),
            true,
        );
        assert!(
            decoded.contains("café"),
            "a genuine head http-equiv declaration must remain effective: {decoded:?}"
        );
    }

    #[test]
    fn recognizes_genuine_head_meta_after_template_content() {
        let decoded = decode_body(
            b"<!doctype html><html><head>\
              <template><body><meta charset=shift_jis></template>\
              <meta charset=iso-8859-1></head><body>caf\xe9</body></html>",
            Some("text/html"),
            true,
        );
        assert!(
            decoded.contains("café"),
            "template content must not close the head for a later genuine declaration: {decoded:?}"
        );
    }

    #[test]
    fn ignores_pseudo_tags_and_meta_after_the_head() {
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head>\
              <div data-example=\"<meta charset=iso-8859-1>\"></div>\
              <meta charset=iso-8859-1>\
              <body>caf\xe9</body></html>",
        );
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head>\
              <meta charset=iso-8859-1 <body>caf\xe9</body></html>",
        );
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head></head>\
              <meta charset=iso-8859-1><body>caf\xe9</body></html>",
        );
        assert_falls_back_to_utf8(
            b"<!doctype html><html><head></head>\
              <body><meta charset=iso-8859-1>caf\xe9</body></html>",
        );
    }

    #[test]
    fn ignores_declarations_not_fully_contained_in_the_scan_window() {
        let mut after_limit = vec![b' '; META_SCAN_LIMIT];
        after_limit.extend(b"<meta charset=iso-8859-1><body>caf\xe9</body>");
        assert_falls_back_to_utf8(&after_limit);

        let mut split_at_limit = vec![b' '; META_SCAN_LIMIT - 5];
        split_at_limit.extend(b"<meta charset=iso-8859-1><body>caf\xe9</body>");
        assert_falls_back_to_utf8(&split_at_limit);
    }
}
