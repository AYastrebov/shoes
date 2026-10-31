//! The authentication exchange: the XML documents openconnect posts
//! (`auth.c:794-1004`) and the ones ocserv answers with
//! (`worker-auth.c:51-106`, `worker-auth.c:594-700`), as
//! draft-mavrogiannopoulos-openconnect-04 §2.2.1–2.2.2 describes them.

use std::io;

use super::xml::{self, Element};

/// What openconnect 9.21 sends (`main.c:1866`, `http.c:1013-1021`). ocserv
/// chooses the shape of its forms by this header (`worker-http.c:468-520`):
/// this prefix selects the `config-auth` documents parsed here, and
/// "Open AnyConnect VPN Agent v3" selects a reduced form that is not.
pub const USER_AGENT: &str = "AnyConnect-compatible OpenConnect VPN Agent v9.21";
const VERSION: &str = "v9.21";

/// openconnect's name for the platform (`library.c:539-558`). ocserv reads
/// `android` and `apple-ios` as mobile (`worker-http.c:430-436`) and
/// applies its mobile DPD and idle timeouts, which are the longer ones.
pub const PLATFORM: &str = if cfg!(target_os = "android") {
    "android"
} else if cfg!(target_os = "ios") {
    "apple-ios"
} else if cfg!(target_os = "macos") {
    "mac-intel"
} else if cfg!(target_os = "windows") {
    "win"
} else {
    "linux-64"
};

pub const IS_MOBILE: bool = cfg!(any(target_os = "android", target_os = "ios"));

fn config_auth(kind: &str) -> Element {
    Element::new("config-auth")
        .with_attribute("client", "vpn")
        .with_attribute("type", kind)
        .with_attribute("aggregate-auth-version", "2")
        .with_child(
            Element::new("version")
                .with_attribute("who", "vpn")
                .with_text(VERSION),
        )
        .with_child(Element::new("device-id").with_text(PLATFORM))
}

const PROLOG: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// The first document (`auth.c:910-944`): `group-access` is the URL being
/// posted to, and `group-select` the configured group, if any.
pub fn init_document(group_access: &str, group: Option<&str>) -> String {
    let mut root =
        config_auth("init").with_child(Element::new("group-access").with_text(group_access));
    if let Some(group) = group {
        root = root.with_child(Element::new("group-select").with_text(group));
    }
    format!("{PROLOG}{}", root.to_xml())
}

/// An `<input>` of the server's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub name: String,
    pub kind: String,
    pub value: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Form {
    pub action: Option<String>,
    pub inputs: Vec<Input>,
    /// A `<select>`: its name and its options' values.
    pub select: Option<(String, Vec<String>)>,
}

/// The server's answer to a posted document.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one per login round; the form is the common case and is read whole"
)]
pub enum Response {
    /// `<auth id="success">`: authenticated. The token is AnyConnect's way
    /// of handing over the cookie (`auth.c:684-686`); ocserv sets it as a
    /// `Set-Cookie` instead.
    Success { session_token: Option<String> },
    /// `<auth id="...">` with a form to fill, or with none and an error.
    Auth {
        id: String,
        form: Option<Form>,
        /// Echoed back verbatim in the reply (`auth.c:661-666`).
        opaque: Option<Element>,
        message: Option<String>,
        error: Option<String>,
    },
}

fn text_child(element: &Element, name: &str) -> Option<String> {
    element
        .child(name)
        .map(Element::text)
        .filter(|t| !t.is_empty())
}

/// Parse the server's document (`auth.c:580-700`).
pub fn parse_response(body: &str) -> io::Result<Response> {
    let root = xml::parse(body)?;
    // The root is `config-auth`; an older server sends `auth` bare.
    let (config_auth, auth) = if root.name == "config-auth" {
        let auth = root.child("auth");
        (Some(&root), auth)
    } else if root.name == "auth" {
        (None, Some(&root))
    } else {
        (Some(&root), None)
    };
    let Some(auth) = auth else {
        if let Some(root) = config_auth
            && let Some(error) = text_child(root, "error")
        {
            return Ok(Response::Auth {
                id: String::new(),
                form: None,
                opaque: None,
                message: None,
                error: Some(error),
            });
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OpenConnect: the server's XML has no \"auth\" element",
        ));
    };
    let id = auth.attribute("id").unwrap_or_default().to_string();
    if id == "success" {
        let session_token = config_auth.and_then(|root| text_child(root, "session-token"));
        return Ok(Response::Success { session_token });
    }
    let form = auth.child("form").map(parse_form).transpose()?;
    Ok(Response::Auth {
        id,
        form,
        opaque: config_auth.and_then(|root| root.child("opaque").cloned()),
        message: text_child(auth, "message"),
        error: text_child(auth, "error")
            .or_else(|| config_auth.and_then(|r| text_child(r, "error"))),
    })
}

fn parse_form(form: &Element) -> io::Result<Form> {
    let method = form.attribute("method").unwrap_or("POST");
    if !method.eq_ignore_ascii_case("post") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("OpenConnect: the server's form wants method {method:?}"),
        ));
    }
    let mut out = Form {
        action: form.attribute("action").map(str::to_string),
        ..Form::default()
    };
    for element in form.elements() {
        match element.name.as_str() {
            "input" => {
                let Some(kind) = element.attribute("type") else {
                    continue;
                };
                if kind == "submit" || kind == "reset" {
                    continue;
                }
                let Some(name) = element.attribute("name") else {
                    continue;
                };
                out.inputs.push(Input {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    value: element.attribute("value").map(str::to_string),
                    label: element.attribute("label").map(str::to_string),
                });
            }
            "select" => {
                let name = element
                    .attribute("name")
                    .unwrap_or("group_list")
                    .to_string();
                // `auth.c:140-148`: an option's value is its `value`
                // attribute, else its text.
                let options = element
                    .elements()
                    .filter(|e| e.name == "option")
                    .map(|e| match e.attribute("value") {
                        Some(v) => v.to_string(),
                        None => e.text(),
                    })
                    .collect();
                out.select = Some((name, options));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// What a form asks for beyond a username, a password and a group, which
/// this client cannot give.
pub fn unsupported_inputs(form: &Form) -> Vec<String> {
    form.inputs
        .iter()
        .filter(|input| !fillable(input))
        .map(|input| match &input.label {
            Some(label) => format!("{} ({})", input.name, label.trim_end_matches(':')),
            None => input.name.clone(),
        })
        .collect()
}

fn fillable(input: &Input) -> bool {
    match input.kind.as_str() {
        "hidden" => true,
        "text" => input.name == "username",
        "password" => input.name == "password",
        _ => false,
    }
}

/// The reply (`auth.c:946-1004`): `opaque` as received, the inputs under
/// `auth`, the group as `group-select` under the root. Refuses a form it
/// cannot fill, naming what it asks for, and a group that is not offered.
pub fn reply_document(
    form: &Form,
    opaque: Option<&Element>,
    username: &str,
    password: &str,
    group: Option<&str>,
) -> io::Result<String> {
    let unsupported = unsupported_inputs(form);
    if !unsupported.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "OpenConnect: the server asks for {}, which this client does not do \
                 (only a username, a password and a group)",
                unsupported.join(", ")
            ),
        ));
    }
    let mut root = config_auth("auth-reply");
    if let Some(opaque) = opaque {
        root = root.with_child(opaque.clone());
    }
    let mut auth = Element::new("auth");
    for input in &form.inputs {
        let value = match input.kind.as_str() {
            "hidden" => input.value.clone().unwrap_or_default(),
            "text" => username.to_string(),
            _ => password.to_string(),
        };
        auth = auth.with_child(Element::new(&input.name).with_text(&value));
    }
    root = root.with_child(auth);
    if let Some((_, options)) = &form.select {
        let chosen = match group {
            Some(group) => {
                if !options.is_empty() && !options.iter().any(|o| o == group) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "OpenConnect: the server offers groups {} and not the configured one",
                            options
                                .iter()
                                .map(|o| format!("{o:?}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
                group.to_string()
            }
            // openconnect's default selection is the first option
            // (`auth.c:97`, `auth.c:168-170`); ocserv lists a previously
            // chosen group first.
            None => options.first().cloned().unwrap_or_default(),
        };
        if !chosen.is_empty() {
            root = root.with_child(Element::new("group-select").with_text(&chosen));
        }
    }
    Ok(format!("{PROLOG}{}", root.to_xml()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    /// ocserv's login form (`worker-auth.c:78-101`, `:594-700`).
    const FORM: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <config-auth client=\"vpn\" type=\"auth-request\">\n\
        <version who=\"sg\">0.1(1)</version>\n<auth id=\"main\">\n\
        <message>Please enter your username and password.</message>\n\
        <form method=\"post\" action=\"/auth\">\n\
        <input type=\"text\" name=\"username\" label=\"Username:\" />\n\
        <input type=\"password\" name=\"password\" label=\"Password:\" />\n\
        <select name=\"group_list\" label=\"Group:\">\n<option>Route</option>\n<option>All</option>\n</select>\n\
        </form></auth>\n</config-auth>";

    /// ocserv's success (`worker-auth.c:50-56`).
    const SUCCESS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <config-auth client=\"vpn\" type=\"complete\">\n<version who=\"sg\">0.1(1)</version>\n\
        <auth id=\"success\">\n<title>SSL VPN Service</title><banner>hi</banner></auth></config-auth>\n";

    #[test]
    fn the_init_document_is_what_openconnect_posts() {
        let doc = init_document("https://vpn.example.com/", Some("Route"));
        assert!(doc.starts_with(PROLOG));
        let root = xml::parse(&doc).unwrap();
        assert_eq!(root.attribute("type"), Some("init"));
        assert_eq!(root.attribute("aggregate-auth-version"), Some("2"));
        assert_eq!(root.child("version").unwrap().attribute("who"), Some("vpn"));
        assert_eq!(root.child("device-id").unwrap().text(), PLATFORM);
        assert_eq!(
            root.child("group-access").unwrap().text(),
            "https://vpn.example.com/"
        );
        assert_eq!(root.child("group-select").unwrap().text(), "Route");
    }

    #[test]
    fn ocservs_form_is_answered_with_the_credentials_and_the_group() {
        let Response::Auth {
            id,
            form,
            opaque,
            message,
            error,
        } = parse_response(FORM).unwrap()
        else {
            panic!("a form");
        };
        assert_eq!(id, "main");
        assert!(opaque.is_none() && error.is_none());
        assert_eq!(
            message.as_deref(),
            Some("Please enter your username and password.")
        );
        let form = form.unwrap();
        assert_eq!(form.action.as_deref(), Some("/auth"));
        assert!(unsupported_inputs(&form).is_empty());
        let reply = reply_document(&form, None, "alice", "p&w", Some("All")).unwrap();
        let root = xml::parse(&reply).unwrap();
        assert_eq!(root.attribute("type"), Some("auth-reply"));
        let auth = root.child("auth").unwrap();
        assert_eq!(auth.child("username").unwrap().text(), "alice");
        assert_eq!(auth.child("password").unwrap().text(), "p&w");
        assert!(reply.contains("<password>p&amp;w</password>"));
        assert_eq!(root.child("group-select").unwrap().text(), "All");

        // No group configured: the first offered.
        let reply = reply_document(&form, None, "alice", "pw", None).unwrap();
        assert_eq!(
            xml::parse(&reply)
                .unwrap()
                .child("group-select")
                .unwrap()
                .text(),
            "Route"
        );
        // A group the server does not offer is refused by listing them.
        let err = reply_document(&form, None, "alice", "pw", Some("Nope")).unwrap_err();
        assert!(err.to_string().contains("\"Route\", \"All\""), "{err}");
    }

    #[test]
    fn success_is_recognised_with_and_without_a_token() {
        assert_eq!(
            parse_response(SUCCESS).unwrap(),
            Response::Success {
                session_token: None
            }
        );
        let anyconnect = "<config-auth client=\"vpn\" type=\"complete\"><session-token>T</session-token>\
                          <auth id=\"success\"/></config-auth>";
        assert_eq!(
            parse_response(anyconnect).unwrap(),
            Response::Success {
                session_token: Some("T".into())
            }
        );
    }

    /// ocserv with two passwords configured asks for the second in its own
    /// form (`worker-auth.c:96-97`, `:560-593`); an OTP server does the
    /// same. Named, not guessed at.
    #[test]
    fn a_second_factor_is_named_and_refused() {
        let doc = "<config-auth client=\"vpn\" type=\"auth-request\"><auth id=\"main\">\
            <message>Please enter your password.</message><form method=\"post\" action=\"/auth\">\
            <input type=\"password\" name=\"secondary_password\" label=\"Password2:\" />\
            </form></auth></config-auth>";
        let Response::Auth { form, .. } = parse_response(doc).unwrap() else {
            panic!("a form");
        };
        let form = form.unwrap();
        assert_eq!(
            unsupported_inputs(&form),
            ["secondary_password (Password2)"]
        );
        let err = reply_document(&form, None, "a", "b", None).unwrap_err();
        assert!(err.to_string().contains("secondary_password"), "{err}");
    }

    /// The `opaque` element goes back as it came, and hidden inputs with
    /// their values (`auth.c:955-961`, `:208-209`).
    #[test]
    fn opaque_and_hidden_inputs_are_echoed() {
        let doc = "<config-auth client=\"vpn\" type=\"auth-request\">\
            <opaque is-for=\"sg\"><tunnel-group>tg</tunnel-group><config-hash>1</config-hash></opaque>\
            <auth id=\"main\"><form><input type=\"hidden\" name=\"tgroup\" value=\"x\"/>\
            <input type=\"text\" name=\"username\"/><input type=\"password\" name=\"password\"/>\
            </form></auth></config-auth>";
        let Response::Auth { form, opaque, .. } = parse_response(doc).unwrap() else {
            panic!("a form");
        };
        let reply = reply_document(&form.unwrap(), opaque.as_ref(), "u", "p", None).unwrap();
        assert!(reply.contains(
            "<opaque is-for=\"sg\"><tunnel-group>tg</tunnel-group><config-hash>1</config-hash></opaque>"
        ));
        assert!(reply.contains("<tgroup>x</tgroup>"));
        assert!(!reply.contains("group-select"));
    }

    #[test]
    fn an_error_without_a_form_is_reported() {
        let doc = "<config-auth client=\"vpn\" type=\"auth-request\"><auth id=\"main\">\
            <error>Login failed</error></auth></config-auth>";
        let Response::Auth { form, error, .. } = parse_response(doc).unwrap() else {
            panic!("an auth");
        };
        assert!(form.is_none());
        assert_eq!(error.as_deref(), Some("Login failed"));
        assert!(parse_response("<html/>").is_err());
    }
}
