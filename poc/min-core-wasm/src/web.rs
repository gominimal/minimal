//! Browser head: a WebSocket as the SSH transport, and a wasm-bindgen surface
//! shaped so `TerminalPane.astro`'s `connect()` can swap `new WebSocket(url)`
//! for it with a thin adapter (see `js/min-socket.mjs`).
//!
//! The relay on the other end of the WebSocket is dumb: it forwards bytes to
//! the daemon's UDS. Everything SSH — key exchange, host key check, auth, the
//! session channel — happens here, in the tab.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use js_sys::{ArrayBuffer, Function, Promise, Uint8Array};
use send_wrapper::SendWrapper;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, spawn_local};
use web_sys::{BinaryType, CloseEvent, Event as DomEvent, MessageEvent, WebSocket};

use crate::attach::{Attach, Event, Grid, Writer};

#[derive(Default)]
struct Shared {
    rx: VecDeque<u8>,
    open: bool,
    /// Set once, on error or close; read as EOF and as the write error.
    closed: Option<String>,
    read_waker: Option<Waker>,
    open_waker: Option<Waker>,
}

impl Shared {
    fn wake_all(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.open_waker.take() {
            w.wake();
        }
    }
}

struct Callbacks {
    _onopen: Closure<dyn FnMut()>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onerror: Closure<dyn FnMut(DomEvent)>,
    _onclose: Closure<dyn FnMut(CloseEvent)>,
}

/// A browser `WebSocket` as `AsyncRead + AsyncWrite`.
///
/// russh's `connect_stream` wants a `Send` stream and its session task is
/// spawned through `russh_util`, which also demands `Send`. JS handles are
/// `!Send`; `SendWrapper` asserts single-threaded use, which is exactly the
/// browser main thread.
pub struct WsStream {
    ws: SendWrapper<WebSocket>,
    shared: Arc<Mutex<Shared>>,
    _callbacks: SendWrapper<Callbacks>,
}

fn js_io_error(value: JsValue) -> io::Error {
    io::Error::other(value.as_string().unwrap_or_else(|| format!("{value:?}")))
}

impl WsStream {
    /// Open `url` and resolve once the socket is open.
    pub async fn connect(url: &str) -> io::Result<Self> {
        let ws = WebSocket::new(url).map_err(js_io_error)?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let shared = Arc::new(Mutex::new(Shared::default()));

        let s = shared.clone();
        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            if let Ok(buf) = e.data().dyn_into::<ArrayBuffer>() {
                let mut g = s.lock().unwrap();
                g.rx.extend(Uint8Array::new(&buf).to_vec());
                if let Some(w) = g.read_waker.take() {
                    w.wake();
                }
            }
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let s = shared.clone();
        let onopen = Closure::<dyn FnMut()>::new(move || {
            let mut g = s.lock().unwrap();
            g.open = true;
            g.wake_all();
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));

        let s = shared.clone();
        let onerror = Closure::<dyn FnMut(DomEvent)>::new(move |_e: DomEvent| {
            let mut g = s.lock().unwrap();
            g.closed.get_or_insert_with(|| "websocket error".to_string());
            g.wake_all();
        });
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        let s = shared.clone();
        let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
            let mut g = s.lock().unwrap();
            g.closed
                .get_or_insert_with(|| format!("websocket closed ({} {})", e.code(), e.reason()));
            g.wake_all();
        });
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        let stream = Self {
            ws: SendWrapper::new(ws),
            shared,
            _callbacks: SendWrapper::new(Callbacks {
                _onopen: onopen,
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            }),
        };

        std::future::poll_fn(|cx| {
            let mut g = stream.shared.lock().unwrap();
            if g.open {
                Poll::Ready(Ok(()))
            } else if let Some(err) = &g.closed {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, err.clone())))
            } else {
                g.open_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;
        Ok(stream)
    }
}

/// Detach every handler and close: after this the JS socket can no longer
/// call into Rust closures that are about to be (or have been) dropped.
fn clear_handlers(ws: &WebSocket) {
    ws.set_onopen(None);
    ws.set_onmessage(None);
    ws.set_onerror(None);
    ws.set_onclose(None);
    let _ = ws.close();
}

impl Drop for WsStream {
    fn drop(&mut self) {
        clear_handlers(&self.ws);
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock().unwrap();
        if g.rx.is_empty() {
            if g.closed.is_some() {
                return Poll::Ready(Ok(())); // EOF
            }
            g.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(g.rx.len());
        let chunk: Vec<u8> = g.rx.drain(..n).collect();
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err) = self.shared.lock().unwrap().closed.clone() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)));
        }
        Poll::Ready(
            self.ws
                .send_with_u8_array(buf)
                .map(|()| buf.len())
                .map_err(js_io_error),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.ws.close();
        Poll::Ready(Ok(()))
    }
}

fn to_js(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

/// An attached session, as seen from JS.
#[wasm_bindgen]
pub struct MinAttach {
    writer: Rc<Writer>,
    _mesh: Option<Rc<MeshLink>>,
}

#[wasm_bindgen]
impl MinAttach {
    /// Keystrokes / pasted bytes into the session PTY.
    pub fn write(&self, data: &[u8]) -> Promise {
        let writer = self.writer.clone();
        let data = data.to_vec();
        future_to_promise(async move {
            writer.write(&data).await.map_err(to_js)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn resize(&self, cols: u32, rows: u32) -> Promise {
        let writer = self.writer.clone();
        future_to_promise(async move {
            writer.resize(Grid { cols, rows }).await.map_err(to_js)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Detach: closes the channel, which leaves the session running.
    pub fn close(&self) -> Promise {
        let writer = self.writer.clone();
        future_to_promise(async move {
            writer.close().await.map_err(to_js)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// Dial `relay_url` (a WebSocket that forwards bytes to the daemon UDS), run
/// the attach handshake for `session_id`, then stream PTY output to `on_data`
/// (Uint8Array) until the channel closes, when `on_close` receives the exit
/// status (number) or `undefined`.
#[wasm_bindgen]
pub async fn attach(
    relay_url: String,
    session_id: String,
    term: String,
    cols: u32,
    rows: u32,
    on_data: Function,
    on_close: Function,
) -> Result<MinAttach, JsValue> {
    console_error_panic_hook::set_once();
    let stream = WsStream::connect(&relay_url).await.map_err(to_js)?;
    let attached = Attach::connect(stream, &session_id, &term, Grid { cols, rows })
        .await
        .map_err(to_js)?;
    let (writer, mut reader) = attached.split();
    spawn_local(async move {
        let mut exit: Option<u32> = None;
        while let Some(event) = reader.next().await {
            match event {
                Event::Data(bytes) | Event::Stderr(bytes) => {
                    let _ = on_data.call1(&JsValue::NULL, &Uint8Array::from(&bytes[..]));
                }
                Event::Exit(code) => exit = Some(code),
                Event::Eof => {}
                Event::Closed => break,
            }
        }
        let code = exit.map(JsValue::from).unwrap_or(JsValue::UNDEFINED);
        let _ = on_close.call1(&JsValue::NULL, &code);
    });
    Ok(MinAttach {
        writer: Rc::new(writer),
        _mesh: None,
    })
}

// ---------------------------------------------------------------------------
// Mesh path: the tab as a WireGuard node, SSH inside the tunnel.
// ---------------------------------------------------------------------------

use crate::wg::{DatagramPipe, WgConfig, WgStack};
use tokio::sync::mpsc;

struct DatagramCallbacks {
    _onopen: Closure<dyn FnMut()>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onerror: Closure<dyn FnMut(DomEvent)>,
    _onclose: Closure<dyn FnMut(CloseEvent)>,
}

/// A browser `WebSocket` carrying one WireGuard datagram per binary frame —
/// the transport a daemon's WebSocket ingress (or a mesh relay) speaks.
pub struct WsDatagrams {
    ws: SendWrapper<WebSocket>,
    _callbacks: SendWrapper<DatagramCallbacks>,
}

impl WsDatagrams {
    pub async fn connect(url: &str) -> io::Result<(DatagramPipe, WsDatagrams)> {
        let ws = WebSocket::new(url).map_err(js_io_error)?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let state = Arc::new(Mutex::new(Shared::default()));
        let (from_network_tx, from_network_rx) = mpsc::channel::<Vec<u8>>(256);
        let (to_network_tx, mut to_network_rx) = mpsc::channel::<Vec<u8>>(256);

        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            if let Ok(buf) = e.data().dyn_into::<ArrayBuffer>() {
                // Datagram semantics: a full queue drops, like UDP.
                let _ = from_network_tx.try_send(Uint8Array::new(&buf).to_vec());
            }
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let s = state.clone();
        let onopen = Closure::<dyn FnMut()>::new(move || {
            let mut g = s.lock().unwrap();
            g.open = true;
            g.wake_all();
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        let s = state.clone();
        let onerror = Closure::<dyn FnMut(DomEvent)>::new(move |_e: DomEvent| {
            let mut g = s.lock().unwrap();
            g.closed.get_or_insert_with(|| "websocket error".to_string());
            g.wake_all();
        });
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        let s = state.clone();
        let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
            let mut g = s.lock().unwrap();
            g.closed
                .get_or_insert_with(|| format!("websocket closed ({} {})", e.code(), e.reason()));
            g.wake_all();
        });
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        // Outbound pump: the stack's datagrams onto the socket. Ends when the
        // stack (the sender) goes away.
        let sender = ws.clone();
        spawn_local(async move {
            while let Some(datagram) = to_network_rx.recv().await {
                if sender.send_with_u8_array(&datagram).is_err() {
                    break;
                }
            }
        });

        // The link owns the closures from here on: if the open below fails,
        // dropping it detaches the handlers from the JS socket, so a late
        // `close` event cannot invoke a dropped closure.
        let link = WsDatagrams {
            ws: SendWrapper::new(ws),
            _callbacks: SendWrapper::new(DatagramCallbacks {
                _onopen: onopen,
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            }),
        };
        std::future::poll_fn(|cx| {
            let mut g = state.lock().unwrap();
            if g.open {
                Poll::Ready(Ok(()))
            } else if let Some(err) = &g.closed {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, err.clone())))
            } else {
                g.open_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;

        Ok((
            DatagramPipe {
                to_network: to_network_tx,
                from_network: from_network_rx,
            },
            link,
        ))
    }
}

impl Drop for WsDatagrams {
    fn drop(&mut self) {
        clear_handlers(&self.ws);
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32], JsValue> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| to_js(format!("key is not base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| to_js("key must be 32 bytes"))
}

/// Attach over the mesh: dial `ws_url` (a WireGuard-over-WebSocket ingress),
/// bring up a WireGuard tunnel to the peer with the given keys and tunnel
/// addresses, open TCP to `peer_ip:ssh_port` inside it, then run the same
/// attach handshake as [`attach`]. Keys are base64 as WireGuard prints them.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn attach_wg(
    ws_url: String,
    private_key_b64: String,
    peer_public_key_b64: String,
    local_ip: String,
    peer_ip: String,
    prefix_len: u8,
    ssh_port: u16,
    session_id: String,
    term: String,
    cols: u32,
    rows: u32,
    on_data: Function,
    on_close: Function,
) -> Result<MinAttach, JsValue> {
    console_error_panic_hook::set_once();
    let cfg = WgConfig {
        private_key: decode_key(&private_key_b64)?,
        peer_public_key: decode_key(&peer_public_key_b64)?,
        local_ip: local_ip.parse().map_err(|e| to_js(format!("local_ip: {e}")))?,
        prefix_len,
        peer_ip: peer_ip.parse().map_err(|e| to_js(format!("peer_ip: {e}")))?,
        persistent_keepalive_secs: Some(25),
        initiate: true,
    };
    let (pipe, link) = WsDatagrams::connect(&ws_url).await.map_err(to_js)?;
    let (stack, driver) = WgStack::new(cfg, pipe);
    spawn_local(driver);
    let stream = stack.connect(ssh_port);
    let attached = Attach::connect(stream, &session_id, &term, Grid { cols, rows })
        .await
        .map_err(to_js)?;
    let (writer, mut reader) = attached.split();
    spawn_local(async move {
        let mut exit: Option<u32> = None;
        while let Some(event) = reader.next().await {
            match event {
                Event::Data(bytes) | Event::Stderr(bytes) => {
                    let _ = on_data.call1(&JsValue::NULL, &Uint8Array::from(&bytes[..]));
                }
                Event::Exit(code) => exit = Some(code),
                Event::Eof => {}
                Event::Closed => break,
            }
        }
        let code = exit.map(JsValue::from).unwrap_or(JsValue::UNDEFINED);
        let _ = on_close.call1(&JsValue::NULL, &code);
    });
    Ok(MinAttach {
        writer: Rc::new(writer),
        _mesh: Some(Rc::new(MeshLink { _stack: stack, _link: link })),
    })
}

/// Keeps the tunnel and its WebSocket alive as long as the attachment.
struct MeshLink {
    _stack: WgStack,
    _link: WsDatagrams,
}
