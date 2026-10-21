//! DNS over TCP to port 53, answered the way the UDP path answers it (FI-1).
//!
//! With fake IP on, a UDP query to port 53 is answered from the pool before
//! routing. A resolver that falls back to TCP -- a truncated answer, or one
//! configured for TCP -- used to go straight through as an ordinary
//! connection, so the app got the real address and the domain rules never saw
//! the name. Each length-prefixed message (RFC 1035 section 4.2.2) is now
//! offered to the same responder; what it does not answer travels to the
//! resolver the app addressed, over one connection the rules judge as any
//! other, opened on the first such query.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::dns::fake_ip::{DnsDecision, FakeIpResponder};
use crate::prepend_stream::PrependStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;

pub(super) async fn handle_dns_over_tcp<S>(
    mut local: S,
    target: NetLocation,
    responder: Arc<FakeIpResponder>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut upstream: Option<Box<dyn AsyncStream>> = None;
    // Queries are taken one at a time. A client may pipeline them; it gets
    // its answers in order, which RFC 7766 allows.
    while let Some(query) = read_message(&mut local).await? {
        let response = match responder.handle_query(&query) {
            DnsDecision::Answer(response) => response,
            DnsDecision::Forward => {
                let upstream = match &mut upstream {
                    Some(upstream) => upstream,
                    None => upstream.insert(connect(&target, &proxy_selector, &resolver).await?),
                };
                write_message(upstream, &query).await?;
                // A zone transfer answers in as many messages as the zone
                // takes, with nothing saying which is the last but the
                // records themselves. The rest of this connection is relayed
                // untouched, so the transfer completes and nothing after it
                // is read out of step.
                if is_zone_transfer(&query) {
                    tokio::io::copy_bidirectional(&mut local, upstream).await?;
                    return Ok(());
                }
                read_message(upstream).await?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{target} closed before answering"),
                    )
                })?
            }
        };
        write_message(&mut local, &response).await?;
    }
    Ok(())
}

/// Whether a query asks for AXFR or IXFR, whose answer spans messages.
fn is_zone_transfer(query: &[u8]) -> bool {
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::RecordType;
    Message::from_vec(query).is_ok_and(|message| {
        message
            .queries
            .iter()
            .any(|q| matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR))
    })
}

/// One length-prefixed message, or `None` at a clean end of stream: one
/// before any byte of a prefix. A prefix cut after its first byte is an
/// error, as is a message cut short.
async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let high = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let low = reader.read_u8().await?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes([high, low]))];
    reader.read_exact(&mut message).await?;
    Ok(Some(message))
}

async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "a DNS message over 65535 bytes cannot be framed for TCP",
        )
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(message).await?;
    writer.flush().await
}

/// The resolver the app addressed, through whatever chain the rules choose.
async fn connect(
    target: &NetLocation,
    proxy_selector: &ClientProxySelector,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<Box<dyn AsyncStream>> {
    match proxy_selector
        .judge(target.clone().into(), resolver)
        .await?
    {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, resolver).await?;
            Ok(match early_data {
                Some(data) if !data.is_empty() => Box::new(PrependStream::new(
                    client_stream,
                    Some(data.into_boxed_slice()),
                )),
                _ => client_stream,
            })
        }
        ConnectDecision::Block => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("DNS over TCP to {target} is blocked by the rules"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::fake_ip::{BypassList, FakeIpNetwork, FakeIpPool};
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::{Name, RData, RecordType};
    use std::str::FromStr;
    use tokio::io::duplex;

    fn responder() -> Arc<FakeIpResponder> {
        let pool = Arc::new(
            FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 8192).unwrap(),
        );
        Arc::new(FakeIpResponder::new(
            pool,
            BypassList::new(std::iter::empty::<&str>()),
        ))
    }

    fn query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    /// A TCP resolver standing in for the one the app addressed: answers
    /// every query with an empty response carrying its id, and counts them.
    async fn upstream() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            while let Some(query) = read_message(&mut stream).await.unwrap() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let request = Message::from_vec(&query).unwrap();
                let response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                write_message(&mut stream, &response.to_vec().unwrap())
                    .await
                    .unwrap();
            }
        });
        (addr, seen)
    }

    /// FI-1: an A query over TCP gets a fake address from the pool, as over
    /// UDP; a query the pool does not answer goes to the resolver addressed,
    /// over one connection; and the client sees both on its own stream.
    #[tokio::test]
    async fn queries_over_tcp_are_answered_like_udp() {
        let responder = responder();
        let (upstream_addr, seen) = upstream().await;
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
                serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap(),
                resolver.clone(),
            ),
        );

        let (near, mut far) = duplex(65536);
        let task = tokio::spawn(handle_dns_over_tcp(
            near,
            NetLocation::from(upstream_addr),
            responder.clone(),
            selector,
            resolver,
        ));

        write_message(&mut far, &query(1, "example.com.", RecordType::A))
            .await
            .unwrap();
        let answer = Message::from_vec(&read_message(&mut far).await.unwrap().unwrap()).unwrap();
        assert_eq!(answer.metadata.id, 1);
        let fake = answer
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .expect("an A answer");
        assert!(responder.pool().is_fake_ip(fake), "{fake} is from the pool");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);

        for id in [2, 3] {
            write_message(&mut far, &query(id, "example.com.", RecordType::TXT))
                .await
                .unwrap();
            let forwarded =
                Message::from_vec(&read_message(&mut far).await.unwrap().unwrap()).unwrap();
            assert_eq!(
                forwarded.metadata.id, id,
                "the resolver's answer comes back"
            );
        }
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);

        drop(far);
        task.await.unwrap().unwrap();
    }

    /// A message that ends mid-way is an error, a clean close is not.
    #[tokio::test]
    async fn a_truncated_message_is_an_error() {
        let (mut near, mut far) = duplex(64);
        far.write_all(&[0, 10, 1, 2]).await.unwrap();
        drop(far);
        assert!(read_message(&mut near).await.is_err());

        let (mut near, far) = duplex(64);
        drop(far);
        assert!(read_message(&mut near).await.unwrap().is_none());

        // Half a length prefix is not a clean close.
        let (mut near, mut far) = duplex(64);
        far.write_all(&[0]).await.unwrap();
        drop(far);
        assert!(read_message(&mut near).await.is_err());
    }

    /// A zone transfer's answer spans several messages: all of them reach
    /// the client, and a query after it gets its own answer, not a leftover.
    #[tokio::test]
    async fn a_zone_transfer_completes_and_framing_holds_after_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            while let Some(query) = read_message(&mut stream).await.unwrap() {
                let request = Message::from_vec(&query).unwrap();
                let frames = if is_zone_transfer(&query) { 3 } else { 1 };
                for _ in 0..frames {
                    let response =
                        Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                    write_message(&mut stream, &response.to_vec().unwrap())
                        .await
                        .unwrap();
                }
            }
        });
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
                serde_yaml::from_str("- masks: 0.0.0.0/0\n  action: allow\n").unwrap(),
                resolver.clone(),
            ),
        );
        let (near, mut far) = duplex(65536);
        let task = tokio::spawn(handle_dns_over_tcp(
            near,
            NetLocation::from(upstream_addr),
            responder(),
            selector,
            resolver,
        ));

        write_message(&mut far, &query(7, "example.com.", RecordType::AXFR))
            .await
            .unwrap();
        for frame in 0..3 {
            let answer =
                tokio::time::timeout(std::time::Duration::from_secs(5), read_message(&mut far))
                    .await
                    .unwrap_or_else(|_| panic!("transfer frame {frame} never arrived"))
                    .unwrap()
                    .unwrap();
            assert_eq!(Message::from_vec(&answer).unwrap().metadata.id, 7);
        }
        write_message(&mut far, &query(8, "example.com.", RecordType::TXT))
            .await
            .unwrap();
        let after = Message::from_vec(&read_message(&mut far).await.unwrap().unwrap()).unwrap();
        assert_eq!(after.metadata.id, 8, "its own answer, not a leftover");

        drop(far);
        task.await.unwrap().unwrap();
    }
}
