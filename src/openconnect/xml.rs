//! The little XML the auth exchange needs: elements, attributes, text.
//!
//! The documents are a few hundred bytes of `config-auth` with a known
//! shape (draft-mavrogiannopoulos-openconnect-04 Appendix B). ocserv reads
//! them by substring search (`worker-auth.c:1532-1718`), openconnect with
//! libxml2 in recovering mode (`auth.c:608-609`). This is in between: a
//! real tree, lenient about what it does not understand (unknown entities,
//! processing instructions, doctype, comments), strict about nesting. A
//! dependency would be measured against the mobile size band for the sake
//! of two document shapes.

use std::io;

/// Deeper than this is not an auth document.
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    pub fn new(name: &str) -> Self {
        Element {
            name: name.to_string(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn with_attribute(mut self, name: &str, value: &str) -> Self {
        self.attributes.push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_text(mut self, text: &str) -> Self {
        self.children.push(Node::Text(text.to_string()));
        self
    }

    pub fn with_child(mut self, child: Element) -> Self {
        self.children.push(Node::Element(child));
        self
    }

    /// The first child element with this name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name == name)
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// The element's direct text, joined and trimmed.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for node in &self.children {
            if let Node::Text(t) = node {
                out.push_str(t);
            }
        }
        out.trim().to_string()
    }

    /// Serialise, escaping what must be escaped.
    pub fn write(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attributes {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            escape_into(v, out);
            out.push('"');
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for child in &self.children {
            match child {
                Node::Element(e) => e.write(out),
                Node::Text(t) => escape_into(t, out),
            }
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }

    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

fn escape_into(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        // An entity is at most `&#x10FFFF;`: ten characters. Looking no
        // further keeps a run of ampersands linear, and a `&` before the
        // `;` starts a new scan rather than ending this one.
        let mut end = None;
        for (j, c) in rest[1..].char_indices().take(10) {
            match c {
                ';' => {
                    end = Some(1 + j);
                    break;
                }
                '&' => break,
                _ => {}
            }
        }
        let Some(end) = end else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(|n| match n.strip_prefix('x') {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => n.parse().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                // Not an entity this understands: keep it as written.
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn malformed(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("OpenConnect: the server's XML is malformed: {what}"),
    )
}

/// The document's root element.
pub fn parse(doc: &str) -> io::Result<Element> {
    let mut parser = Parser {
        rest: doc,
        depth: 0,
    };
    parser.skip_prolog()?;
    let root = parser.element()?;
    parser.skip_misc();
    if !parser.rest.trim().is_empty() {
        return Err(malformed("content after the root element"));
    }
    Ok(root)
}

struct Parser<'a> {
    rest: &'a str,
    depth: usize,
}

impl<'a> Parser<'a> {
    /// Whitespace, the XML declaration, comments, a doctype, processing
    /// instructions: everything before the root element.
    fn skip_prolog(&mut self) -> io::Result<()> {
        loop {
            self.rest = self.rest.trim_start();
            if self.rest.starts_with("<?") {
                let end = self
                    .rest
                    .find("?>")
                    .ok_or_else(|| malformed("unterminated <?"))?;
                self.rest = &self.rest[end + 2..];
            } else if self.rest.starts_with("<!--") {
                let end = self
                    .rest
                    .find("-->")
                    .ok_or_else(|| malformed("unterminated comment"))?;
                self.rest = &self.rest[end + 3..];
            } else if self.rest.starts_with("<!") {
                let end = self
                    .rest
                    .find('>')
                    .ok_or_else(|| malformed("unterminated <!"))?;
                self.rest = &self.rest[end + 1..];
            } else {
                return Ok(());
            }
        }
    }

    fn skip_misc(&mut self) {
        loop {
            self.rest = self.rest.trim_start();
            if self.rest.starts_with("<!--") {
                match self.rest.find("-->") {
                    Some(end) => self.rest = &self.rest[end + 3..],
                    None => return,
                }
            } else if self.rest.starts_with("<?") {
                match self.rest.find("?>") {
                    Some(end) => self.rest = &self.rest[end + 2..],
                    None => return,
                }
            } else {
                return;
            }
        }
    }

    /// An element starting at `<`.
    fn element(&mut self) -> io::Result<Element> {
        if self.depth >= MAX_DEPTH {
            return Err(malformed("nested too deep"));
        }
        let Some(after_lt) = self.rest.strip_prefix('<') else {
            return Err(malformed("expected an element"));
        };
        self.rest = after_lt;
        let name = self.name()?;
        let mut element = Element::new(name);
        loop {
            self.rest = self.rest.trim_start();
            if let Some(after) = self.rest.strip_prefix("/>") {
                self.rest = after;
                return Ok(element);
            }
            if let Some(after) = self.rest.strip_prefix('>') {
                self.rest = after;
                break;
            }
            let key = self.name()?;
            self.rest = self.rest.trim_start();
            let Some(after_eq) = self.rest.strip_prefix('=') else {
                return Err(malformed("attribute without a value"));
            };
            self.rest = after_eq.trim_start();
            let quote = self
                .rest
                .chars()
                .next()
                .filter(|c| *c == '"' || *c == '\'')
                .ok_or_else(|| malformed("unquoted attribute"))?;
            let body = &self.rest[1..];
            let end = body
                .find(quote)
                .ok_or_else(|| malformed("unterminated attribute"))?;
            element
                .attributes
                .push((key.to_string(), unescape(&body[..end])));
            self.rest = &body[end + 1..];
        }
        self.depth += 1;
        loop {
            if let Some(after) = self.rest.strip_prefix("</") {
                let end = after
                    .find('>')
                    .ok_or_else(|| malformed("unterminated end tag"))?;
                if after[..end].trim() != element.name {
                    return Err(malformed("mismatched end tag"));
                }
                self.rest = &after[end + 1..];
                self.depth -= 1;
                return Ok(element);
            }
            if self.rest.starts_with("<!--") {
                let end = self
                    .rest
                    .find("-->")
                    .ok_or_else(|| malformed("unterminated comment"))?;
                self.rest = &self.rest[end + 3..];
                continue;
            }
            if let Some(after) = self.rest.strip_prefix("<![CDATA[") {
                let end = after
                    .find("]]>")
                    .ok_or_else(|| malformed("unterminated CDATA"))?;
                element.children.push(Node::Text(after[..end].to_string()));
                self.rest = &after[end + 3..];
                continue;
            }
            if self.rest.starts_with("<?") {
                let end = self
                    .rest
                    .find("?>")
                    .ok_or_else(|| malformed("unterminated <?"))?;
                self.rest = &self.rest[end + 2..];
                continue;
            }
            if self.rest.starts_with('<') {
                let child = self.element()?;
                element.children.push(Node::Element(child));
                continue;
            }
            if self.rest.is_empty() {
                return Err(malformed("unterminated element"));
            }
            let end = self.rest.find('<').unwrap_or(self.rest.len());
            element
                .children
                .push(Node::Text(unescape(&self.rest[..end])));
            self.rest = &self.rest[end..];
        }
    }

    fn name(&mut self) -> io::Result<&'a str> {
        let end = self
            .rest
            .find(|c: char| c.is_whitespace() || matches!(c, '>' | '/' | '='))
            .unwrap_or(self.rest.len());
        if end == 0 {
            return Err(malformed("expected a name"));
        }
        let name = &self.rest[..end];
        self.rest = &self.rest[end..];
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    /// ocserv's login form, as `worker-auth.c:78-101` build it.
    const OCSERV_FORM: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <config-auth client=\"vpn\" type=\"auth-request\">\n\
        <version who=\"sg\">0.1(1)</version>\n\
        <auth id=\"main\">\n\
        <message>Please enter your username and password.</message>\n\
        <form method=\"post\" action=\"/auth\">\n\
        <input type=\"text\" name=\"username\" label=\"Username:\" />\n\
        <input type=\"password\" name=\"password\" label=\"Password:\" />\n\
        <select name=\"group_list\" label=\"Group:\">\n\
        <option>admins</option>\n<option>users</option>\n</select>\n\
        </form></auth>\n</config-auth>";

    #[test]
    fn ocservs_form_parses_into_its_parts() {
        let root = parse(OCSERV_FORM).unwrap();
        assert_eq!(root.name, "config-auth");
        assert_eq!(root.attribute("type"), Some("auth-request"));
        let auth = root.child("auth").unwrap();
        assert_eq!(auth.attribute("id"), Some("main"));
        assert_eq!(
            auth.child("message").unwrap().text(),
            "Please enter your username and password."
        );
        let form = auth.child("form").unwrap();
        assert_eq!(form.attribute("action"), Some("/auth"));
        let inputs: Vec<_> = form
            .elements()
            .filter(|e| e.name == "input")
            .map(|e| (e.attribute("type").unwrap(), e.attribute("name").unwrap()))
            .collect();
        assert_eq!(inputs, [("text", "username"), ("password", "password")]);
        let options: Vec<_> = form
            .child("select")
            .unwrap()
            .elements()
            .map(Element::text)
            .collect();
        assert_eq!(options, ["admins", "users"]);
    }

    #[test]
    fn entities_decode_and_encode() {
        let root = parse("<a x=\"&lt;&quot;&#65;&#x42;\">a &amp; b &unknown; &gt;</a>").unwrap();
        assert_eq!(root.attribute("x"), Some("<\"AB"));
        assert_eq!(root.text(), "a & b &unknown; >");
        let doc = Element::new("auth")
            .with_child(Element::new("password").with_text("p<&>\"w"))
            .to_xml();
        assert_eq!(
            doc,
            "<auth><password>p&lt;&amp;&gt;&quot;w</password></auth>"
        );
        assert_eq!(
            parse(&doc).unwrap().child("password").unwrap().text(),
            "p<&>\"w"
        );
    }

    #[test]
    fn comments_cdata_and_the_prolog_are_handled() {
        let root = parse(
            "<?xml version=\"1.0\"?><!DOCTYPE x><!-- c --><r><!-- in --><![CDATA[<raw>]]><e/></r>\n",
        )
        .unwrap();
        assert_eq!(root.text(), "<raw>");
        assert!(root.child("e").is_some());
    }

    /// A run of ampersands is decoded in linear time, and an entity longer
    /// than any real one is left as written.
    #[test]
    fn a_run_of_ampersands_is_linear() {
        // Two million: the scan that looked for the `;` from every `&`
        // took a minute here, this takes milliseconds.
        let run = "&".repeat(2_000_000) + ";";
        let started = std::time::Instant::now();
        assert_eq!(unescape(&run), run);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(unescape("&notanentityatall;"), "&notanentityatall;");
        assert_eq!(unescape("&amp;&lt;&#x10FFFF;x"), "&<\u{10FFFF}x");
    }

    #[test]
    fn broken_documents_are_refused() {
        for doc in [
            "<a>",
            "<a></b>",
            "<a x=y/>",
            "<a x=\"1/>",
            "<a/><b/>",
            "text",
            "",
            "<a><b></a>",
        ] {
            assert!(parse(doc).is_err(), "{doc:?}");
        }
        let deep = "<a>".repeat(40) + &"</a>".repeat(40);
        assert!(parse(&deep).is_err());
    }
}
