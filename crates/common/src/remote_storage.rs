use crate::fetchers::{GcsUrl, ReqwestUrl};
use crate::file_cache;
use crate::file_cache::CachingDownloader;
use anyhow::Result;
use google_cloud_storage::client::Storage;
use ot::OpTracker;

use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RemoteStorage {
    client: Storage,
    cache: file_cache::FileCache,
}

impl RemoteStorage {
    #[tracing::instrument]
    pub async fn new(cache_dir: PathBuf, with_gcloud_auth: bool) -> Result<Self> {
        Self::new_with_offline(cache_dir, with_gcloud_auth, false).await
    }

    /// Same as [Self::new], but with an `offline` flag. When `offline=true`, any cache
    /// miss surfaces as an error rather than a silent network fetch — see
    /// [`file_cache::FileCacheError::OfflineCacheMiss`]. Pair with `--no-fetch` so the
    /// flag means "I am offline; use only what's cached" end-to-end.
    #[tracing::instrument]
    pub async fn new_with_offline(
        cache_dir: PathBuf,
        with_gcloud_auth: bool,
        offline: bool,
    ) -> Result<Self> {
        let cache = file_cache::FileCache::new_with_offline(cache_dir, offline)?;

        let client = if with_gcloud_auth {
            Storage::builder().build().await?
        } else {
            Storage::builder()
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await?
        };
        Ok(Self { client, cache })
    }

    /// Returns the cached copy of `url`, or downloads it, after the sha256
    /// check.
    ///
    /// `placement` is the `cgroup.procs` of the cgroup the download's
    /// connections must open in, e.g. the classifier leaf of the box a build
    /// runs for (NET-155). Each connection then leaves from a socket created
    /// in that cgroup, so the egress rules that match the cgroup decide it.
    /// `None` opens the connections in the caller's own cgroup. The cache
    /// lookup and the content-hash check are the same either way.
    ///
    /// The host name is asked of the first `nameserver` in
    /// `/etc/resolv.conf`, from a UDP socket created in the same cgroup, so
    /// those rules decide the name query too.
    ///
    /// `admits_nothing` says that the egress rules of the placement admit no
    /// destination. The download then refuses every connection before it
    /// sends a name query. It has no effect without a placement.
    #[tracing::instrument]
    pub async fn download_web_with_verification_and_caching(
        &self,
        url: &str,
        sha256: &str,
        placement: Option<&Path>,
        admits_nothing: bool,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        if let Some(procs) = placement {
            let placement = placed::Placement {
                procs,
                admits_nothing,
            };
            return placed::download(&self.cache, url, sha256, placement, op).await;
        }
        let client = reqwest::Client::new();
        let backend = (&client, &self.cache);
        backend
            .download(ReqwestUrl::try_from(url)?, sha256, op)
            .await
            .map_err(|e| match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => anyhow::Error::from(e),
            })
    }

    #[tracing::instrument]
    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        let backend = (&self.client, &self.cache);
        backend
            .download(
                GcsUrl {
                    bucket: format!("projects/_/buckets/{bucket_id}"),
                    object: file.to_string(),
                },
                sha256,
                op,
            )
            .await
            .map_err(|e| match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => anyhow::Error::from(e),
            })
    }

    #[tracing::instrument(skip(file))]
    pub async fn upload(&self, bucket_id: &str, file_path: &str, file: File) -> Result<()> {
        let _response = self
            .client
            .write_object(
                format!("projects/_/buckets/{bucket_id}"),
                file_path,
                tokio::fs::File::from_std(file),
            )
            .send_buffered()
            .await?;

        Ok(())
    }
}

/// Web downloads whose connections open in a given cgroup (NET-155).
///
/// A socket belongs to the cgroup of the process that creates it, and the
/// egress rules match that cgroup, not the cgroup of the process that later
/// connects it. One thread of this process cannot join another cgroup alone.
/// So a placed download sends its requests through a relay on loopback,
/// which reqwest takes as its proxy. For each connection, the relay has a
/// short-lived child process join the cgroup and create the socket, then
/// connects that socket to the destination itself. TLS stays end to end:
/// an `https` request reaches the relay as a `CONNECT` tunnel.
mod placed {
    use super::*;
    use crate::fetchers::ReqwestUrl;
    use anyhow::Context;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, Mutex, PoisonError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// The cgroup a placed download opens its connections in.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Placement<'a> {
        /// The `cgroup.procs` of the cgroup.
        pub(super) procs: &'a Path,
        /// The egress rules that match the cgroup admit no destination.
        pub(super) admits_nothing: bool,
    }

    /// The most bytes of a request head the relay reads before it gives up.
    const MAX_HEAD: usize = 16 * 1024;

    /// Downloads `url` into `cache`, with every connection opened in the
    /// cgroup whose `cgroup.procs` is `procs`.
    pub(super) async fn download(
        cache: &file_cache::FileCache,
        url: &str,
        sha256: &str,
        placement: Placement<'_>,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        let url = ReqwestUrl::try_from(url)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("could not open the local relay for a placed download")?;
        let addr = listener.local_addr()?;
        // Only this download's client knows the token, so no other process
        // on the host can open a connection through the relay.
        let auth = format!("Bearer {}", crate::random_alphanumeric(32));
        let relay = Arc::new(Relay {
            procs: placement.procs.to_path_buf(),
            admits_nothing: placement.admits_nothing,
            nameserver: None,
            auth: auth.clone(),
            failure: Mutex::new(None),
        });
        let _serving = AbortOnDrop(tokio::spawn(serve(listener, relay.clone())));

        let proxy = reqwest::Proxy::all(format!("http://{addr}"))?
            .custom_http_auth(reqwest::header::HeaderValue::from_str(&auth)?);
        // No idle connection is kept, so a plain-HTTP connection to the
        // relay is never reused for another destination.
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .pool_max_idle_per_host(0)
            .build()?;
        let backend = (&client, cache);
        backend.download(url, sha256, op).await.map_err(|e| {
            let e = match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => anyhow::Error::from(e),
            };
            // The relay's own failure says which destination the placed
            // connection could not reach, which reqwest's error does not.
            match relay
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                Some(failure) => e.context(failure),
                None => e,
            }
        })
    }

    /// Aborts the relay's accept loop when the download ends.
    struct AbortOnDrop(tokio::task::JoinHandle<()>);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    struct Relay {
        /// The `cgroup.procs` of the cgroup each connection opens in.
        procs: PathBuf,
        /// The cgroup's egress rules admit no destination: refuse every
        /// connection before its host name is resolved.
        admits_nothing: bool,
        /// The name server the relay asks, from a socket created in the
        /// cgroup. `None` takes the first `nameserver` of `/etc/resolv.conf`.
        nameserver: Option<SocketAddr>,
        /// The `Proxy-Authorization` value this download's client sends.
        auth: String,
        /// The last destination the relay could not reach, and why.
        failure: Mutex<Option<String>>,
    }

    async fn serve(listener: TcpListener, relay: Arc<Relay>) {
        loop {
            let conn = match listener.accept().await {
                Ok((conn, _)) => conn,
                Err(e) => {
                    tracing::debug!(error = %e, "the relay of a placed download could not accept");
                    continue;
                }
            };
            let relay = relay.clone();
            tokio::spawn(async move {
                if let Err(e) = relay.handle(conn).await {
                    tracing::debug!(error = %e, "a relayed connection of a placed download ended");
                }
            });
        }
    }

    impl Relay {
        async fn handle(&self, mut client: TcpStream) -> io::Result<()> {
            let mut head = Vec::with_capacity(1024);
            let end = loop {
                if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                if head.len() >= MAX_HEAD {
                    return Err(io::Error::other("the request head is too long"));
                }
                let mut buf = [0u8; 4096];
                let n = client.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                head.extend_from_slice(&buf[..n]);
            };
            let rest = head.split_off(end);
            let text = String::from_utf8(head).map_err(io::Error::other)?;
            let mut lines = text.split("\r\n");
            let request = lines.next().unwrap_or_default();
            let headers: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
            let mut parts = request.split(' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            let version = parts.next().unwrap_or("HTTP/1.1");

            let is_auth = |line: &str| {
                line.split_once(':').is_some_and(|(name, _)| {
                    name.trim().eq_ignore_ascii_case("proxy-authorization")
                })
            };
            let authorized = headers.iter().filter(|line| is_auth(line)).any(|line| {
                line.split_once(':')
                    .is_some_and(|(_, v)| v.trim() == self.auth)
            });
            if !authorized {
                client
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\n\r\n",
                    )
                    .await?;
                return Ok(());
            }

            let tunnel = method.eq_ignore_ascii_case("CONNECT");
            let (host, port, forwarded) = if tunnel {
                let (host, port) = target
                    .rsplit_once(':')
                    .and_then(|(h, p)| Some((h.to_string(), p.parse::<u16>().ok()?)))
                    .ok_or_else(|| io::Error::other(format!("bad tunnel target {target}")))?;
                (host, port, None)
            } else {
                let url = url::Url::parse(target).map_err(io::Error::other)?;
                let host = url
                    .host_str()
                    .ok_or_else(|| io::Error::other("the request names no host"))?
                    .to_string();
                let port = url
                    .port_or_known_default()
                    .ok_or_else(|| io::Error::other("the request names no port"))?;
                // The origin gets the request in origin form, without the
                // relay's own credential.
                let mut out = format!(
                    "{method} {} {version}\r\n",
                    &url[url::Position::BeforePath..]
                );
                for line in headers.iter().filter(|l| !is_auth(l)) {
                    out.push_str(line);
                    out.push_str("\r\n");
                }
                out.push_str("\r\n");
                (host, port, Some(out))
            };
            let host = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();

            let mut upstream = match self.connect(&host, port).await {
                Ok(upstream) => upstream,
                Err(e) => {
                    let failure = format!("could not connect to {host}:{port}: {e}");
                    tracing::debug!(cgroup = %self.procs.display(), "{failure}");
                    *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = Some(failure);
                    client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                        .await?;
                    return Ok(());
                }
            };
            match forwarded {
                None => {
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                }
                Some(head) => upstream.write_all(head.as_bytes()).await?,
            }
            upstream.write_all(&rest).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok(())
        }

        /// A connection to `host:port` from a socket created in the cgroup.
        async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            if self.admits_nothing {
                // Rules that admit nothing refuse the name query as well,
                // so the relay sends none and fails at once.
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the egress rules admit no destination",
                ));
            }
            let addrs = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => vec![ip],
                Err(_) => {
                    let nameserver = match self.nameserver {
                        Some(nameserver) => nameserver,
                        None => system_nameserver()?,
                    };
                    lookup_in_cgroup(&self.procs, nameserver, host).await?
                }
            };
            let mut last = None;
            for ip in addrs {
                let addr = SocketAddr::new(ip, port);
                let procs = self.procs.clone();
                let socket = tokio::task::spawn_blocking(move || {
                    socket_in_cgroup(&procs, addr.is_ipv6(), SocketKind::Stream)
                })
                .await
                .map_err(io::Error::other)??;
                let socket = std::net::TcpStream::from(socket);
                socket.set_nonblocking(true)?;
                match tokio::net::TcpSocket::from_std_stream(socket)
                    .connect(addr)
                    .await
                {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"))
            }))
        }
    }

    /// How long the relay waits for one answer from the name server.
    const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// The first `nameserver` of `/etc/resolv.conf`, on port 53.
    fn system_nameserver() -> io::Result<SocketAddr> {
        let text = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| {
            io::Error::new(e.kind(), format!("could not read /etc/resolv.conf: {e}"))
        })?;
        first_nameserver(&text).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "/etc/resolv.conf names no name server",
            )
        })
    }

    /// The first `nameserver` in the text of a `resolv.conf`, on port 53.
    fn first_nameserver(text: &str) -> Option<SocketAddr> {
        let conf = resolv_conf::Config::parse(text).ok()?;
        let ip: IpAddr = conf.nameservers.first()?.into();
        Some(SocketAddr::new(ip, 53))
    }

    /// The addresses of `host`: its A and AAAA records, asked of
    /// `nameserver` from a UDP socket created in the cgroup whose
    /// `cgroup.procs` is `procs`. So the egress rules that match the cgroup
    /// decide the query as well as the connection (NET-155).
    async fn lookup_in_cgroup(
        procs: &Path,
        nameserver: SocketAddr,
        host: &str,
    ) -> io::Result<Vec<IpAddr>> {
        use hickory_proto::rr::RecordType;

        let procs = procs.to_path_buf();
        let socket = tokio::task::spawn_blocking(move || {
            socket_in_cgroup(&procs, nameserver.is_ipv6(), SocketKind::Datagram)
        })
        .await
        .map_err(io::Error::other)??;
        let socket = std::net::UdpSocket::from(socket);
        socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        socket.connect(nameserver).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("could not reach the name server {nameserver}: {e}"),
            )
        })?;
        let mut addrs = Vec::new();
        let mut last = None;
        for rtype in [RecordType::A, RecordType::AAAA] {
            match ask(&socket, host, rtype).await {
                Ok(found) => addrs.extend(found),
                Err(e) => last = Some(e),
            }
        }
        if addrs.is_empty() {
            return Err(last.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"))
            }));
        }
        Ok(addrs)
    }

    /// Sends one query for `host` on the connected `socket` and returns the
    /// addresses its answer carries.
    async fn ask(
        socket: &tokio::net::UdpSocket,
        host: &str,
        rtype: hickory_proto::rr::RecordType,
    ) -> io::Result<Vec<IpAddr>> {
        use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
        use hickory_proto::rr::{Name, RData};

        let name = Name::from_utf8(format!("{}.", host.trim_end_matches('.')))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{host}: {e}")))?;
        let id: u16 = rand::random();
        let mut query = Message::query();
        query.metadata.id = id;
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name, rtype));
        let bytes = query.to_vec().map_err(io::Error::other)?;
        socket.send(&bytes).await?;
        let mut buf = vec![0u8; 4096];
        let reply = tokio::time::timeout(LOOKUP_TIMEOUT, async {
            loop {
                let n = socket.recv(&mut buf).await?;
                // A datagram that is not the answer to this query is not
                // trusted; the wait goes on for the real one.
                match Message::from_vec(&buf[..n]) {
                    Ok(reply)
                        if reply.metadata.id == id
                            && reply.metadata.message_type == MessageType::Response =>
                    {
                        return Ok::<_, io::Error>(reply);
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the name server did not answer for {host}"),
            )
        })??;
        match reply.metadata.response_code {
            ResponseCode::NoError => {}
            code => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not resolve {host}: {code}"),
                ));
            }
        }
        Ok(reply
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect())
    }

    /// The kind of socket a child makes in a cgroup.
    #[derive(Debug, Clone, Copy)]
    enum SocketKind {
        /// A TCP socket, for a connection.
        Stream,
        /// A UDP socket, for a name query.
        Datagram,
    }

    /// A socket that a child process created after it joined the cgroup
    /// whose `cgroup.procs` is `procs`, so the socket belongs to that cgroup.
    #[cfg(target_os = "linux")]
    fn socket_in_cgroup(
        procs: &Path,
        v6: bool,
        kind: SocketKind,
    ) -> io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsRawFd;

        let procs_file = std::fs::OpenOptions::new()
            .write(true)
            .open(procs)
            .map_err(|e| {
                io::Error::new(e.kind(), format!("could not open {}: {e}", procs.display()))
            })?;
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let ty = match kind {
            SocketKind::Stream => libc::SOCK_STREAM,
            SocketKind::Datagram => libc::SOCK_DGRAM,
        };
        let (procs_fd, theirs_fd) = (procs_file.as_raw_fd(), theirs.as_raw_fd());
        // SAFETY: the child calls only async-signal-safe functions (`write`,
        // `socket`, `sendmsg`, `_exit`) on memory it owns, so the locks other
        // threads of this process held at the fork never matter to it.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: see above. The child never returns.
            unsafe { socket_child(procs_fd, theirs_fd, domain, ty) }
        }
        drop(theirs);
        drop(procs_file);
        let received = receive_socket(&ours);
        let mut status = 0;
        // SAFETY: `pid` is the child this call forked, reaped exactly once.
        while unsafe { libc::waitpid(pid, &mut status, 0) } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
        match received? {
            Report::Socket(fd) => Ok(fd),
            Report::Join(errno) => Err(io::Error::new(
                io::Error::from_raw_os_error(errno).kind(),
                format!(
                    "could not move a process into {}: {}",
                    procs.display(),
                    io::Error::from_raw_os_error(errno)
                ),
            )),
            Report::Create(errno) => Err(io::Error::from_raw_os_error(errno)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn socket_in_cgroup(
        _procs: &Path,
        _v6: bool,
        _kind: SocketKind,
    ) -> io::Result<std::os::fd::OwnedFd> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a download placed in a cgroup runs only on Linux",
        ))
    }

    /// What the child process that creates a placed socket reports.
    #[cfg(target_os = "linux")]
    enum Report {
        Socket(std::os::fd::OwnedFd),
        /// The child could not join the cgroup: the errno.
        Join(i32),
        /// The child could not create the socket: the errno.
        Create(i32),
    }

    /// The child's report: one step byte (0 done, 1 join, 2 create) and an
    /// errno, little-endian.
    #[cfg(target_os = "linux")]
    const REPORT_LEN: usize = 5;

    /// The forked child: joins the cgroup, creates the socket, sends it to
    /// the parent over `out`, and exits.
    ///
    /// # Safety
    ///
    /// Call only in the child of a `fork`. It never returns.
    #[cfg(target_os = "linux")]
    unsafe fn socket_child(
        procs: libc::c_int,
        out: libc::c_int,
        domain: libc::c_int,
        ty: libc::c_int,
    ) -> ! {
        // SAFETY: plain syscalls on descriptors the parent opened for the
        // child, and on stack memory; no allocation, no lock.
        unsafe {
            let mut report = [0u8; REPORT_LEN];
            let mut fd = -1;
            if libc::write(procs, b"0".as_ptr().cast(), 1) != 1 {
                report[0] = 1;
                report[1..].copy_from_slice(&(*libc::__errno_location()).to_le_bytes());
            } else {
                fd = libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0);
                if fd < 0 {
                    report[0] = 2;
                    report[1..].copy_from_slice(&(*libc::__errno_location()).to_le_bytes());
                }
            }
            let mut iov = libc::iovec {
                iov_base: report.as_mut_ptr().cast(),
                iov_len: report.len(),
            };
            let mut control = [0u64; 4];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if fd >= 0 {
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd);
            }
            libc::sendmsg(out, &msg, 0);
            libc::_exit(0)
        }
    }

    /// Reads the child's report, and the socket it sent with it.
    #[cfg(target_os = "linux")]
    fn receive_socket(sock: &std::os::unix::net::UnixStream) -> io::Result<Report> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let mut report = [0u8; REPORT_LEN];
        let mut iov = libc::iovec {
            iov_base: report.as_mut_ptr().cast(),
            iov_len: report.len(),
        };
        let mut control = [0u64; 4];
        // SAFETY: a zeroed `msghdr` is valid; the pointers set next outlive
        // the `recvmsg` call that reads them.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;
        let n = loop {
            // SAFETY: `msg` points at live buffers of the lengths it names.
            let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut socket = None;
        // SAFETY: the kernel filled `control` and set `msg_controllen`; the
        // macros walk only within it.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>());
                    socket = Some(OwnedFd::from_raw_fd(fd));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if n as usize != REPORT_LEN {
            return Err(io::Error::other(
                "the process that creates a placed socket exited without a report",
            ));
        }
        let errno = i32::from_le_bytes([report[1], report[2], report[3], report[4]]);
        match (report[0], socket) {
            (0, Some(fd)) => Ok(Report::Socket(fd)),
            (1, _) => Ok(Report::Join(errno)),
            (2, _) => Ok(Report::Create(errno)),
            _ => Err(io::Error::other(
                "the process that creates a placed socket sent no socket",
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Serves `body` to every HTTP request on a loopback port.
        async fn serve_body(body: &'static [u8]) -> std::net::SocketAddr {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (mut conn, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut buf = [0u8; 1024];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                            let n = conn.read(&mut buf).await.unwrap();
                            if n == 0 {
                                return;
                            }
                            head.extend_from_slice(&buf[..n]);
                        }
                        let head = String::from_utf8_lossy(&head).to_string();
                        assert!(
                            head.starts_with("GET /pkg-1.0.tar.gz HTTP/1.1\r\n"),
                            "the origin gets the request in origin form: {head}"
                        );
                        assert!(
                            !head.to_ascii_lowercase().contains("proxy-authorization"),
                            "the relay's credential never reaches the origin: {head}"
                        );
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        conn.write_all(reply.as_bytes()).await.unwrap();
                        conn.write_all(body).await.unwrap();
                    });
                }
            });
            addr
        }

        /// NET-155: a placed web download reaches its destination through
        /// the relay, from a socket that a child created after it wrote
        /// itself into the placement's `cgroup.procs`, and the content-hash
        /// check still applies. A plain file stands in for `cgroup.procs`:
        /// the child's write lands in it, and the socket comes back.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_placed_download_connects_from_the_placement() {
            use sha2::Digest;
            let body: &'static [u8] = b"the source archive";
            let sha = hex::encode(sha2::Sha256::digest(body));
            let addr = serve_body(body).await;
            let tmp = tempfile::tempdir().unwrap();
            let procs = tmp.path().join("cgroup.procs");
            std::fs::write(&procs, "").unwrap();
            let cache =
                file_cache::FileCache::new_with_offline(tmp.path().join("cache"), false).unwrap();
            let url = format!("http://{addr}/pkg-1.0.tar.gz");

            let placement = Placement {
                procs: &procs,
                admits_nothing: false,
            };
            let path = download(&cache, &url, &sha, placement, &OpTracker::new_root())
                .await
                .expect("the placed download succeeds");
            assert_eq!(std::fs::read(path).unwrap(), body);
            assert_eq!(
                std::fs::read_to_string(&procs).unwrap(),
                "0",
                "the child that made the socket joined the placement"
            );

            // A destination the placed socket cannot reach names itself.
            let closed = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let closed_addr = closed.local_addr().unwrap();
            drop(closed);
            let refused = download(
                &cache,
                &format!("http://{closed_addr}/other-1.0.tar.gz"),
                &sha,
                placement,
                &OpTracker::new_root(),
            )
            .await
            .expect_err("nothing listens there");
            assert!(
                refused
                    .to_string()
                    .starts_with(&format!("could not connect to {closed_addr}: ")),
                "{refused:#}"
            );

            // A placement whose rules admit nothing resolves no name and
            // opens no socket: the child never joins the placement.
            std::fs::write(&procs, "").unwrap();
            let sealed = download(
                &cache,
                "http://downloads.example.invalid/sealed-1.0.tar.gz",
                &sha,
                Placement {
                    procs: &procs,
                    admits_nothing: true,
                },
                &OpTracker::new_root(),
            )
            .await
            .expect_err("rules that admit nothing refuse the connection");
            assert_eq!(
                sealed.to_string(),
                "could not connect to downloads.example.invalid:80: \
                 the egress rules admit no destination",
                "{sealed:#}"
            );
            assert_eq!(std::fs::read_to_string(&procs).unwrap(), "");
        }

        /// NET-155: the child that makes a placed socket writes itself into
        /// the placement's `cgroup.procs` before it creates the socket, and a
        /// placement it cannot open is refused with its path. A plain file
        /// stands in for `cgroup.procs`.
        #[cfg(target_os = "linux")]
        #[test]
        fn a_placed_socket_is_created_in_the_named_cgroup() {
            let tmp = tempfile::tempdir().unwrap();
            let procs = tmp.path().join("cgroup.procs");
            std::fs::write(&procs, "").unwrap();
            let fd = socket_in_cgroup(&procs, false, SocketKind::Stream).expect("a placed socket");
            let socket = std::net::TcpStream::from(fd);
            socket.set_nonblocking(true).unwrap();
            assert_eq!(std::fs::read_to_string(&procs).unwrap(), "0");
            let refused = socket_in_cgroup(
                Path::new("/nonexistent/cgroup.procs"),
                false,
                SocketKind::Stream,
            )
            .expect_err("no cgroup, no socket");
            assert!(
                refused.to_string().contains("/nonexistent/cgroup.procs"),
                "{refused}"
            );
        }

        /// A name server on loopback that answers every A query for
        /// `pkg.test.` with 127.0.0.1, and every other query with no
        /// address.
        async fn serve_names() -> SocketAddr {
            use hickory_proto::op::{Message, ResponseCode};
            use hickory_proto::rr::rdata::A;
            use hickory_proto::rr::{RData, Record, RecordType};

            let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = socket.local_addr().unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                    let request = Message::from_vec(&buf[..n]).unwrap();
                    let mut reply =
                        Message::response(request.metadata.id, request.metadata.op_code);
                    let question = request.queries[0].clone();
                    let known = question.name().to_string() == "pkg.test.";
                    reply.metadata.response_code = if known {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    };
                    if known && question.query_type() == RecordType::A {
                        reply.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                        ));
                    }
                    reply.add_query(question);
                    let bytes = reply.to_vec().unwrap();
                    socket.send_to(&bytes, from).await.unwrap();
                }
            });
            addr
        }

        /// NET-155: a placed download asks for a host name from a UDP socket
        /// that a child created after it wrote itself into the placement's
        /// `cgroup.procs`. So the egress rules of the placement decide the
        /// name query, not only the connection. A plain file stands in for
        /// `cgroup.procs`.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_placed_name_query_leaves_from_the_placement() {
            let nameserver = serve_names().await;
            let tmp = tempfile::tempdir().unwrap();
            let procs = tmp.path().join("cgroup.procs");
            std::fs::write(&procs, "").unwrap();

            let addrs = lookup_in_cgroup(&procs, nameserver, "pkg.test")
                .await
                .expect("the name resolves");
            assert_eq!(addrs, vec![IpAddr::from(std::net::Ipv4Addr::LOCALHOST)]);
            assert_eq!(
                std::fs::read_to_string(&procs).unwrap(),
                "0",
                "the child that made the query socket joined the placement"
            );

            let missing = lookup_in_cgroup(&procs, nameserver, "missing.test")
                .await
                .expect_err("no such name");
            assert!(
                missing
                    .to_string()
                    .starts_with("could not resolve missing.test: "),
                "{missing}"
            );

            // A placement the child cannot join sends no query.
            let refused = lookup_in_cgroup(
                Path::new("/nonexistent/cgroup.procs"),
                nameserver,
                "pkg.test",
            )
            .await
            .expect_err("no cgroup, no query");
            assert!(
                refused.to_string().contains("/nonexistent/cgroup.procs"),
                "{refused}"
            );
        }

        /// The relay asks the first `nameserver` that `/etc/resolv.conf`
        /// names, on port 53.
        #[test]
        fn the_first_nameserver_is_asked() {
            let text = "search example.com\nnameserver 10.0.0.53\nnameserver 1.1.1.1\n";
            assert_eq!(
                first_nameserver(text),
                Some("10.0.0.53:53".parse().unwrap())
            );
            assert_eq!(first_nameserver("search example.com\n"), None);
        }
    }
}
