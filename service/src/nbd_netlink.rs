// Copyright (C) 2026 Datadog, Inc. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Minimal client of the Linux NBD generic netlink interface (`linux/nbd-netlink.h`).
//!
//! Unlike the `NBD_SET_SOCK`/`NBD_DO_IT` ioctls, a device configured through netlink outlives
//! the process which configured it: when its connections die, the kernel requeues in-flight
//! requests and waits up to the dead connection timeout for a new server to reconfigure it.
//! This is what lets a restarted or upgraded nydusd take over a device in use.

use std::io::{Error, Result};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | 0x4000);

const NLMSG_HDR_LEN: usize = 16;
const GENL_HDR_LEN: usize = 4;
const NLA_HDR_LEN: usize = 4;
const RECV_BUF_LEN: usize = 32 << 10;

const NBD_GENL_FAMILY_NAME: &str = "nbd";
const NBD_GENL_VERSION: u8 = 1;

const NBD_CMD_CONNECT: u8 = 1;
const NBD_CMD_DISCONNECT: u8 = 2;
const NBD_CMD_RECONFIGURE: u8 = 3;

const NBD_ATTR_INDEX: u16 = 1;
const NBD_ATTR_SIZE_BYTES: u16 = 2;
const NBD_ATTR_BLOCK_SIZE_BYTES: u16 = 3;
const NBD_ATTR_SERVER_FLAGS: u16 = 5;
const NBD_ATTR_CLIENT_FLAGS: u16 = 6;
const NBD_ATTR_SOCKETS: u16 = 7;
const NBD_ATTR_DEAD_CONN_TIMEOUT: u16 = 8;
const NBD_ATTR_BACKEND_IDENTIFIER: u16 = 10;
const NBD_SOCK_ITEM: u16 = 1;
const NBD_SOCK_FD: u16 = 1;

/// Parameters of a device to connect or reconfigure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    pub index: u32,
    pub size_bytes: u64,
    pub block_size: u64,
    pub server_flags: u64,
    /// Seconds the kernel waits for a new connection before failing requests, once all the
    /// connections of the device are dead.
    pub dead_conn_timeout: u64,
    /// Identifies the server owning the device; reconfiguring requires the same identifier.
    pub backend_id: String,
}

/// Netlink attribute builder.
#[derive(Default)]
struct Attrs(Vec<u8>);

impl Attrs {
    fn put(&mut self, ty: u16, payload: &[u8]) -> &mut Self {
        let len = NLA_HDR_LEN + payload.len();
        self.0.extend_from_slice(&(len as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(payload);
        self.0.resize(align4(self.0.len()), 0);
        self
    }

    fn put_u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    fn put_u64(&mut self, ty: u16, v: u64) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    fn put_str(&mut self, ty: u16, v: &str) -> &mut Self {
        let mut s = v.as_bytes().to_vec();
        s.push(0);
        self.put(ty, &s)
    }

    fn put_nested(&mut self, ty: u16, nested: &Attrs) -> &mut Self {
        self.put(ty | NLA_F_NESTED, &nested.0)
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Encode a generic netlink request.
fn encode_request(family: u16, cmd: u8, version: u8, seq: u32, attrs: &Attrs) -> Vec<u8> {
    let len = NLMSG_HDR_LEN + GENL_HDR_LEN + attrs.0.len();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&(len as u32).to_ne_bytes());
    msg.extend_from_slice(&family.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&[cmd, version, 0, 0]);
    msg.extend_from_slice(&attrs.0);
    msg
}

/// Iterate over the netlink attributes of `buf`, yielding `(type, payload)`.
fn parse_attrs(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut attrs = Vec::new();
    while buf.len() >= NLA_HDR_LEN {
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < NLA_HDR_LEN || len > buf.len() {
            break;
        }
        attrs.push((ty, &buf[NLA_HDR_LEN..len]));
        buf = &buf[align4(len).min(buf.len())..];
    }
    attrs
}

fn attr<'a>(attrs: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(t, _)| *t == ty).map(|(_, p)| *p)
}

#[cfg(test)]
fn attr_u32(attrs: &[(u16, &[u8])], ty: u16) -> Option<u32> {
    attr(attrs, ty)
        .and_then(|p| p.get(..4))
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

fn attr_u16(attrs: &[(u16, &[u8])], ty: u16) -> Option<u16> {
    attr(attrs, ty)
        .and_then(|p| p.get(..2))
        .map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
}

/// A reply to a request: the attributes of each message carrying data, or the error the
/// kernel acknowledged the request with.
fn parse_replies(mut buf: &[u8], seq: u32) -> Result<(Vec<Vec<u8>>, bool)> {
    let mut payloads = Vec::new();
    let mut acked = false;
    while buf.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes([buf[4], buf[5]]);
        let msg_seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(einval!("nbd_netlink: truncated netlink message"));
        }
        let body = &buf[NLMSG_HDR_LEN..len];
        if msg_seq == seq {
            match ty {
                NLMSG_ERROR => {
                    let code = body
                        .get(..4)
                        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                        .ok_or_else(|| einval!("nbd_netlink: truncated netlink error"))?;
                    if code != 0 {
                        return Err(Error::from_raw_os_error(-code));
                    }
                    acked = true;
                }
                NLMSG_DONE => acked = true,
                _ if body.len() >= GENL_HDR_LEN => payloads.push(body[GENL_HDR_LEN..].to_vec()),
                _ => {}
            }
        }
        buf = &buf[align4(len).min(buf.len())..];
    }
    Ok((payloads, acked))
}

/// A generic netlink socket bound to the NBD family.
pub struct NbdNetlink {
    sock: OwnedFd,
    family: u16,
    seq: u32,
}

impl NbdNetlink {
    /// Open a generic netlink socket and resolve the NBD family.
    pub fn open() -> Result<Self> {
        // Safe because the arguments are valid and the returned fd is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        // Safe because `fd` is a valid file descriptor owned by nobody else.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut nl = NbdNetlink {
            sock,
            family: GENL_ID_CTRL,
            seq: 0,
        };
        let mut attrs = Attrs::default();
        attrs.put_str(CTRL_ATTR_FAMILY_NAME, NBD_GENL_FAMILY_NAME);
        let replies = nl.request(CTRL_CMD_GETFAMILY, 1, &attrs)?;
        nl.family = replies
            .iter()
            .find_map(|p| attr_u16(&parse_attrs(p), CTRL_ATTR_FAMILY_ID))
            .ok_or_else(|| enoent!("nbd_netlink: NBD generic netlink family not found"))?;
        Ok(nl)
    }

    fn request(&mut self, cmd: u8, version: u8, attrs: &Attrs) -> Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let msg = encode_request(self.family, cmd, version, self.seq, attrs);
        // Safe because the kernel address is zeroed apart from its family.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // Safe because `msg` and `addr` are valid for the duration of the call.
        let sent = unsafe {
            libc::sendto(
                self.sock.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(Error::last_os_error());
        }

        let mut payloads = Vec::new();
        let mut buf = vec![0u8; RECV_BUF_LEN];
        loop {
            // Safe because `buf` is valid for `buf.len()` bytes.
            let n = unsafe {
                libc::recv(
                    self.sock.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let (mut p, acked) = parse_replies(&buf[..n as usize], self.seq)?;
            payloads.append(&mut p);
            if acked {
                return Ok(payloads);
            }
        }
    }

    fn device_attrs(cfg: &DeviceConfig, socks: &[RawFd]) -> Attrs {
        let mut sockets = Attrs::default();
        for fd in socks {
            let mut item = Attrs::default();
            item.put_u32(NBD_SOCK_FD, *fd as u32);
            sockets.put_nested(NBD_SOCK_ITEM, &item);
        }
        let mut attrs = Attrs::default();
        attrs
            .put_u32(NBD_ATTR_INDEX, cfg.index)
            .put_u64(NBD_ATTR_DEAD_CONN_TIMEOUT, cfg.dead_conn_timeout)
            .put_str(NBD_ATTR_BACKEND_IDENTIFIER, &cfg.backend_id)
            .put_nested(NBD_ATTR_SOCKETS, &sockets);
        attrs
    }

    /// Configure device `cfg.index` to be served through the given connections.
    pub fn connect(&mut self, cfg: &DeviceConfig, socks: &[RawFd]) -> Result<()> {
        let mut attrs = Self::device_attrs(cfg, socks);
        attrs
            .put_u64(NBD_ATTR_SIZE_BYTES, cfg.size_bytes)
            .put_u64(NBD_ATTR_BLOCK_SIZE_BYTES, cfg.block_size)
            .put_u64(NBD_ATTR_SERVER_FLAGS, cfg.server_flags)
            // No NBD_CFLAG_DESTROY_ON_DISCONNECT: the device stays in the pool of the nbd module
            // after a disconnect.
            .put_u64(NBD_ATTR_CLIENT_FLAGS, 0);
        self.request(NBD_CMD_CONNECT, NBD_GENL_VERSION, &attrs)
            .map(|_| ())
    }

    /// Replace the dead connections of a connected device.
    pub fn reconfigure(&mut self, cfg: &DeviceConfig, socks: &[RawFd]) -> Result<()> {
        let attrs = Self::device_attrs(cfg, socks);
        self.request(NBD_CMD_RECONFIGURE, NBD_GENL_VERSION, &attrs)
            .map(|_| ())
    }

    /// Disconnect a device, failing its pending requests.
    pub fn disconnect(&mut self, index: u32) -> Result<()> {
        let mut attrs = Attrs::default();
        attrs.put_u32(NBD_ATTR_INDEX, index);
        self.request(NBD_CMD_DISCONNECT, NBD_GENL_VERSION, &attrs)
            .map(|_| ())
    }
}

/// Parse the device index from a device path like `/dev/nbd3`.
pub fn device_index(path: &str) -> Result<u32> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("nbd"))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| einval!(format!("invalid NBD device path {}", path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(len: u32, ty: u16, seq: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&len.to_ne_bytes());
        h.extend_from_slice(&ty.to_ne_bytes());
        h.extend_from_slice(&0u16.to_ne_bytes());
        h.extend_from_slice(&seq.to_ne_bytes());
        h.extend_from_slice(&0u32.to_ne_bytes());
        h
    }

    #[test]
    fn test_encode_request() {
        let mut attrs = Attrs::default();
        attrs
            .put_u32(NBD_ATTR_INDEX, 3)
            .put_str(NBD_ATTR_BACKEND_IDENTIFIER, "id");
        let msg = encode_request(0x20, NBD_CMD_CONNECT, 1, 7, &attrs);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + GENL_HDR_LEN + 8 + 8);
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize,
            msg.len()
        );
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), 0x20);
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 7);
        assert_eq!(&msg[16..18], &[NBD_CMD_CONNECT, 1]);
        let parsed = parse_attrs(&msg[NLMSG_HDR_LEN + GENL_HDR_LEN..]);
        assert_eq!(attr_u32(&parsed, NBD_ATTR_INDEX), Some(3));
        assert_eq!(
            attr(&parsed, NBD_ATTR_BACKEND_IDENTIFIER),
            Some(&b"id\0"[..])
        );
    }

    #[test]
    fn test_parse_replies() {
        /// Payloads and acknowledgment parsed, or errno of the reply.
        type Want = std::result::Result<(usize, bool), i32>;
        let tests: Vec<(&str, Vec<u8>, Want)> = vec![
            (
                "Ack",
                {
                    let mut m = header(20, NLMSG_ERROR, 5);
                    m.extend_from_slice(&0i32.to_ne_bytes());
                    m
                },
                Ok((0, true)),
            ),
            (
                "Error",
                {
                    let mut m = header(20, NLMSG_ERROR, 5);
                    m.extend_from_slice(&(-libc::EBUSY).to_ne_bytes());
                    m
                },
                Err(libc::EBUSY),
            ),
            (
                "DataThenAck",
                {
                    let mut attrs = Attrs::default();
                    attrs.put_u32(NBD_ATTR_INDEX, 9);
                    let mut m = header(
                        (NLMSG_HDR_LEN + GENL_HDR_LEN + attrs.0.len()) as u32,
                        0x20,
                        5,
                    );
                    m.extend_from_slice(&[NBD_CMD_CONNECT, 1, 0, 0]);
                    m.extend_from_slice(&attrs.0);
                    let mut ack = header(20, NLMSG_ERROR, 5);
                    ack.extend_from_slice(&0i32.to_ne_bytes());
                    m.extend_from_slice(&ack);
                    m
                },
                Ok((1, true)),
            ),
            (
                "OtherSequence",
                {
                    let mut m = header(20, NLMSG_ERROR, 4);
                    m.extend_from_slice(&(-libc::EBUSY).to_ne_bytes());
                    m
                },
                Ok((0, false)),
            ),
        ];
        for (name, buf, want) in tests {
            let got = parse_replies(&buf, 5).map(|(p, acked)| (p.len(), acked));
            match want {
                Ok(w) => assert_eq!(got.unwrap(), w, "{name}"),
                Err(code) => assert_eq!(got.unwrap_err().raw_os_error(), Some(code), "{name}"),
            }
        }
    }

    #[test]
    fn test_device_index() {
        let tests = [
            ("/dev/nbd0", Some(0)),
            ("/dev/nbd17", Some(17)),
            ("nbd3", Some(3)),
            ("/dev/sda", None),
            ("/dev/nbd", None),
        ];
        for (path, want) in tests {
            assert_eq!(device_index(path).ok(), want, "{path}");
        }
    }
}
