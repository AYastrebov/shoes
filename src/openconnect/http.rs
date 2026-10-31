//! HTTP/1.1 over the tunnel's TLS stream: enough of a client for the auth
//! exchange and the `CONNECT`, nothing more. Requests are built into one
//! buffer; responses are read through a buffer that keeps whatever arrives
//! past the end, since after `CONNECT` that is the tunnel's first frame.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// A server that talks this much before the end of its headers is not an
/// OpenConnect server.
const MAX_HEAD: usize = 16 * 1024;
/// An auth document is a few hundred bytes; a megabyte is a web page
/// behind camouflage, or an attack on memory.
const MAX_BODY: usize = 1024 * 1024;

pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub host: &'a str,
    pub user_agent: &'a str,
    pub cookies: &'a [(String, String)],
    pub headers: &'a [(&'a str, String)],
    /// Content type and body.
    pub body: Option<(&'a str, &'a [u8])>,
}

impl Request<'_> {
    /// What [`Request::to_bytes`] would produce, in bytes, without
    /// producing it: the padding is sized from this.
    pub fn encoded_len(&self) -> usize {
        let mut len = self.method.len() + 1 + self.target.len() + " HTTP/1.1\r\n".len();
        len += "Host: ".len() + self.host.len() + 2;
        len += "User-Agent: ".len() + self.user_agent.len() + 2;
        if !self.cookies.is_empty() {
            len += "Cookie: ".len() + 2;
            for (i, (name, value)) in self.cookies.iter().enumerate() {
                len += name.len() + 1 + value.len() + if i > 0 { 2 } else { 0 };
            }
        }
        for (name, value) in self.headers {
            len += name.len() + 2 + value.len() + 2;
        }
        if let Some((content_type, body)) = self.body {
            len += "Content-Type: ".len() + content_type.len() + 2;
            len += "Content-Length: ".len() + body.len().to_string().len() + 2;
            len += body.len();
        }
        len + 2
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", self.method, self.target).as_bytes());
        out.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());
        out.extend_from_slice(format!("User-Agent: {}\r\n", self.user_agent).as_bytes());
        if !self.cookies.is_empty() {
            out.extend_from_slice(b"Cookie: ");
            for (i, (name, value)) in self.cookies.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b"; ");
                }
                out.extend_from_slice(format!("{name}={value}").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
        }
        for (name, value) in self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if let Some((content_type, body)) = self.body {
            out.extend_from_slice(
                format!(
                    "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                    body.len()
                )
                .as_bytes(),
            );
        }
        out.extend_from_slice(b"\r\n");
        if let Some((_, body)) = self.body {
            out.extend_from_slice(body);
        }
        out
    }
}

/// A response's status line and headers. Names are lowercased.
#[derive(Debug, Default)]
pub struct Head {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// The first header of this name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every header of this name, in order: `X-CSTP-DNS` and the split
    /// routes repeat.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `Set-Cookie` values, as (name, value) without their attributes.
    pub fn cookies(&self) -> impl Iterator<Item = (&str, &str)> {
        self.all("set-cookie").filter_map(|line| {
            let first = line.split(';').next()?;
            let (name, value) = first.split_once('=')?;
            Some((name.trim(), value.trim()))
        })
    }

    fn parse(head: &[u8]) -> io::Result<Self> {
        let text =
            std::str::from_utf8(head).map_err(|_| invalid("the response head is not text"))?;
        let mut lines = text.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut fields = status_line.splitn(3, ' ');
        let version = fields.next().unwrap_or_default();
        let status = fields
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|_| version.starts_with("HTTP/1."))
            .ok_or_else(|| {
                let printable: String = status_line
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(120)
                    .collect();
                invalid(&format!("not an HTTP response: {printable:?}"))
            })?;
        let reason = fields.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
        Ok(Head {
            status,
            reason,
            headers,
        })
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("OpenConnect: {what}"))
}

/// Reads responses off a stream, keeping what arrives past them.
#[derive(Default)]
pub struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    async fn fill<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "OpenConnect: the server closed the connection",
            ));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    pub async fn head<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> io::Result<Head> {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = Head::parse(&self.buf[..end])?;
                self.buf.drain(..end + 4);
                return Ok(head);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(invalid("the server's response has no end to its headers"));
            }
            self.fill(stream).await?;
        }
    }

    /// The body `head` announces: by `Content-Length`, by chunks, or none.
    pub async fn body<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        head: &Head,
    ) -> io::Result<Vec<u8>> {
        if head
            .get("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
        {
            return self.chunked(stream).await;
        }
        let len = match head.get("content-length") {
            Some(v) => v
                .parse::<usize>()
                .map_err(|_| invalid("a Content-Length that is not a number"))?,
            None => return Ok(Vec::new()),
        };
        if len > MAX_BODY {
            return Err(invalid("the response body is too large"));
        }
        while self.buf.len() < len {
            self.fill(stream).await?;
        }
        Ok(self.buf.drain(..len).collect())
    }

    async fn chunked<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                    break end;
                }
                if self.buf.len() > MAX_HEAD {
                    return Err(invalid("a chunk size line without end"));
                }
                self.fill(stream).await?;
            };
            let size_text = std::str::from_utf8(&self.buf[..line_end])
                .map_err(|_| invalid("a chunk size that is not text"))?;
            let size_text = size_text.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| invalid("a chunk size that is not hexadecimal"))?;
            self.buf.drain(..line_end + 2);
            if size == 0 {
                // The trailer: headers, then a blank line.
                loop {
                    if let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                        self.buf.drain(..end + 2);
                        if end == 0 {
                            return Ok(body);
                        }
                        continue;
                    }
                    self.fill(stream).await?;
                }
            }
            if body.len() + size > MAX_BODY {
                return Err(invalid("the response body is too large"));
            }
            while self.buf.len() < size + 2 {
                self.fill(stream).await?;
            }
            body.extend_from_slice(&self.buf[..size]);
            self.buf.drain(..size + 2);
        }
    }

    pub fn into_pending(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[tokio::test]
    async fn a_request_is_written_as_the_references_write_it() {
        let cookies = vec![("webvpn".to_string(), "abc".to_string())];
        let headers = vec![("X-CSTP-Version", "1".to_string())];
        let request = Request {
            method: "CONNECT",
            target: "/CSCOSSLC/tunnel",
            host: "vpn.example.com:8443",
            user_agent: "agent",
            cookies: &cookies,
            headers: &headers,
            body: None,
        };
        assert_eq!(
            String::from_utf8(request.to_bytes()).unwrap(),
            "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: vpn.example.com:8443\r\n\
             User-Agent: agent\r\nCookie: webvpn=abc\r\nX-CSTP-Version: 1\r\n\r\n"
        );
        assert_eq!(request.encoded_len(), request.to_bytes().len());
        let two_cookies = vec![
            ("webvpn".to_string(), "abc".to_string()),
            ("webvpncontext".to_string(), "d".to_string()),
        ];
        let request = Request {
            cookies: &two_cookies,
            ..request
        };
        assert_eq!(request.encoded_len(), request.to_bytes().len());
        let request = Request {
            method: "POST",
            target: "/",
            host: "h",
            user_agent: "a",
            cookies: &[],
            headers: &[],
            body: Some(("text/xml", b"<x/>")),
        };
        assert!(
            String::from_utf8(request.to_bytes())
                .unwrap()
                .ends_with("Content-Type: text/xml\r\nContent-Length: 4\r\n\r\n<x/>")
        );
        assert_eq!(request.encoded_len(), request.to_bytes().len());
    }

    #[tokio::test]
    async fn a_response_with_a_body_and_cookies_is_read_and_the_rest_kept() {
        let mut reader = Reader::default();
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: webvpn=tok; Secure\r\n\
              Set-Cookie: webvpnc=; expires=x\r\nX-CSTP-DNS: 1.1.1.1\r\nX-CSTP-DNS: 8.8.8.8\r\n\r\n\
              hellonext"
                .to_vec(),
        );
        let head = reader.head(&mut stream).await.unwrap();
        assert_eq!((head.status, head.reason.as_str()), (200, "OK"));
        assert_eq!(
            head.cookies().collect::<Vec<_>>(),
            [("webvpn", "tok"), ("webvpnc", "")]
        );
        assert_eq!(
            head.all("x-cstp-dns").collect::<Vec<_>>(),
            ["1.1.1.1", "8.8.8.8"]
        );
        assert_eq!(reader.body(&mut stream, &head).await.unwrap(), b"hello");
        assert_eq!(reader.into_pending(), b"next");
    }

    #[tokio::test]
    async fn a_chunked_body_is_joined() {
        let mut reader = Reader::default();
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext\r\nde\r\n0\r\n\r\ntail"
                .to_vec(),
        );
        let head = reader.head(&mut stream).await.unwrap();
        assert_eq!(reader.body(&mut stream, &head).await.unwrap(), b"abcde");
        assert_eq!(reader.into_pending(), b"tail");
    }

    #[tokio::test]
    async fn not_http_is_said_so() {
        let mut reader = Reader::default();
        let mut stream = std::io::Cursor::new(b"SSH-2.0-OpenSSH\r\n\r\n".to_vec());
        let err = reader.head(&mut stream).await.unwrap_err();
        assert!(err.to_string().contains("not an HTTP response"), "{err}");
    }
}
