//! Incremental RTSP/1.0 & HTTP/1.1 message parser and serializer for CarPlay control & event channels.

use indexmap::IndexMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspRequest {
    /// For requests: `"POST"`, `"GET"`, `"SETUP"`, `"RECORD"`, `"TEARDOWN"`, etc.
    /// For responses arriving on the reverse event channel: `"RTSP/1.0"` or `"HTTP/1.1"`.
    pub method: String,
    pub path: String,
    pub protocol: String,
    /// Lowercased header names -> header values.
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RtspResponse {
    pub status: u16,
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
}

impl Default for RtspResponse {
    fn default() -> Self {
        Self {
            status: 200,
            headers: IndexMap::new(),
            body: Vec::new(),
        }
    }
}

impl RtspResponse {
    pub fn ok() -> Self {
        Self::default()
    }

    pub fn with_status(status: u16) -> Self {
        Self {
            status,
            headers: IndexMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_body(content_type: &str, body: Vec<u8>) -> Self {
        let mut headers = IndexMap::new();
        headers.insert("Content-Type".to_string(), content_type.to_string());
        Self {
            status: 200,
            headers,
            body,
        }
    }
}

pub struct ParsedRtspBatch {
    pub messages: Vec<RtspRequest>,
    pub rest: Vec<u8>,
}

/// Parses zero or more complete RTSP/HTTP messages from a byte buffer, returning any partial tail in `rest`.
pub fn parse_messages(buffer: &[u8]) -> ParsedRtspBatch {
    let mut messages = Vec::new();
    let mut offset = 0usize;

    while offset < buffer.len() {
        let slice = &buffer[offset..];
        let Some(hdr_end) = find_header_end(slice) else {
            break;
        };
        let header_bytes = &slice[..hdr_end];
        let sep_len = if slice[hdr_end..].starts_with(b"\r\n\r\n") {
            4
        } else {
            2
        };
        let header_text = String::from_utf8_lossy(header_bytes);
        let mut lines = header_text.lines();
        let Some(start_line) = lines.next() else {
            offset += hdr_end + sep_len;
            continue;
        };
        let mut parts = start_line.trim().splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let protocol = parts.next().unwrap_or("RTSP/1.0").to_string();

        let mut headers = IndexMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let content_len = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        let total_msg_len = hdr_end + sep_len + content_len;
        if slice.len() < total_msg_len {
            break;
        }

        let body = slice[hdr_end + sep_len..total_msg_len].to_vec();
        messages.push(RtspRequest {
            method,
            path,
            protocol,
            headers,
            body,
        });
        offset += total_msg_len;
    }

    ParsedRtspBatch {
        messages,
        rest: buffer[offset..].to_vec(),
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some(i);
        }
    }
    None
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        453 => "Not Enough Bandwidth",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "OK",
    }
}

/// Serializes an RTSP/HTTP response matching the request's protocol (`RTSP/1.0` or `HTTP/1.1`) and `CSeq`.
pub fn build_response(request: &RtspRequest, response: &RtspResponse) -> Vec<u8> {
    let proto = if request.protocol.starts_with("HTTP/") {
        request.protocol.as_str()
    } else {
        "RTSP/1.0"
    };
    let mut head = format!(
        "{proto} {} {}\r\nServer: AirTunes/377.40.00\r\n",
        response.status,
        reason_phrase(response.status)
    );
    if let Some(cseq) = request.headers.get("cseq") {
        head.push_str(&format!("CSeq: {cseq}\r\n"));
    }
    for (k, v) in &response.headers {
        if !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("cseq") {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", response.body.len()));

    let mut wire = head.into_bytes();
    wire.extend_from_slice(&response.body);
    wire
}

/// Serializes a client or reverse-event RTSP request.
pub fn build_request(
    method: &str,
    path: &str,
    cseq: u32,
    content_type: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = format!("{method} {path} RTSP/1.0\r\nCSeq: {cseq}\r\n");
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for &(k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || content_type.is_some() {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}
