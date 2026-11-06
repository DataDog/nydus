// Copyright (C) 2026 Datadog, Inc. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Minimal client of the Linux NBD generic netlink interface (`linux/nbd-netlink.h`).
//!
//! Unlike the `NBD_SET_SOCK`/`NBD_DO_IT` ioctls, a device configured through netlink outlives
//! the process which configured it: when its connections die, the kernel requeues in-flight
//! requests and waits up to the dead connection timeout for a new server to reconfigure it.
//! This is what lets a restarted or upgraded nydusd take over a device in use.

use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::fd::{FromRawFd, RawFd};

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLMSG_ERROR: u16 = 0x2;
const NLA_F_NESTED: u16 = 0x8000;

const NLMSG_HDR_LEN: usize = 16;
const GENL_HDR_LEN: usize = 4;
const NLA_HDR_LEN: usize = 4;

const NBD_GENL_FAMILY_NAME: &str = "nbd";
const NBD_GENL_VERSION: u8 = 1;

const NBD_CMD_CONNECT: u8 = 1;
const NBD_CMD_DISCONNECT: u8 = 2;
const NBD_CMD_RECONFIGURE: u8 = 3;

const NBD_ATTR_INDEX: u16 = 1;
const NBD_ATTR_SIZE_BYTES: u16 = 2;
const NBD_ATTR_BLOCK_SIZE_BYTES: u16 = 3;
const NBD_ATTR_SERVER_FLAGS: u16 = 5;
const NBD_ATTR_SOCKETS: u16 = 7;
const NBD_ATTR_DEAD_CONN_TIMEOUT: u16 = 8;
const NBD_ATTR_BACKEND_IDENTIFIER: u16 = 10;
const NBD_SOCK_ITEM: u16 = 1;
const NBD_SOCK_FD: u16 = 1;

/// Parameters of a device to connect or reconfigure.
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

/// Netlink attributes.
#[derive(Default)]
struct Attrs(Vec<u8>);

impl Attrs {
    fn put(&mut self, ty: u16, payload: &[u8]) -> &mut Self {
        let len = (NLA_HDR_LEN + payload.len()) as u16;
        self.0.extend_from_slice(&len.to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(payload);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
        self
    }

    fn put_u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    fn put_u64(&mut self, ty: u16, v: u64) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    fn put_str(&mut self, ty: u16, v: &str) -> &mut Self {
        self.put(ty, &[v.as_bytes(), &[0]].concat())
    }

    fn put_nested(&mut self, ty: u16, nested: &Attrs) -> &mut Self {
        self.put(ty | NLA_F_NESTED, &nested.0)
    }

    /// Parse the attributes of `buf` into `(type, payload)` pairs.
    fn parse(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
        let mut attrs = Vec::new();
        while buf.len() >= NLA_HDR_LEN {
            let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
            let ty = u16::from_ne_bytes([buf[2], buf[3]]);
            if len < NLA_HDR_LEN || len > buf.len() {
                break;
            }
            attrs.push((ty, &buf[NLA_HDR_LEN..len]));
            buf = &buf[len.next_multiple_of(4).min(buf.len())..];
        }
        attrs
    }
}

/// Encode a generic netlink request, which the kernel acknowledges.
fn encode_request(family: u16, cmd: u8, version: u8, attrs: &Attrs) -> Vec<u8> {
    let len = (NLMSG_HDR_LEN + GENL_HDR_LEN + attrs.0.len()) as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&family.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    // Sequence number and port id: requests are sent one at a time, to the kernel.
    msg.extend_from_slice(&[0; 8]);
    msg.extend_from_slice(&[cmd, version, 0, 0]);
    msg.extend_from_slice(&attrs.0);
    msg
}

/// Parse the netlink messages of `buf` replying to a request, keeping the attributes of the
/// first one carrying data in `reply`. Returns whether the kernel acknowledged the request.
fn parse_replies(mut buf: &[u8], reply: &mut Option<Vec<u8>>) -> Result<bool> {
    while buf.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes([buf[4], buf[5]]);
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(einval!("nbd_netlink: truncated netlink message"));
        }
        let body = &buf[NLMSG_HDR_LEN..len];
        if ty == NLMSG_ERROR {
            let code = body
                .get(..4)
                .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                .ok_or_else(|| einval!("nbd_netlink: truncated netlink error"))?;
            return match code {
                0 => Ok(true),
                _ => Err(Error::from_raw_os_error(-code)),
            };
        }
        if reply.is_none() {
            *reply = body.get(GENL_HDR_LEN..).map(<[u8]>::to_vec);
        }
        buf = &buf[len.next_multiple_of(4).min(buf.len())..];
    }
    Ok(false)
}

/// A generic netlink socket bound to the NBD family.
pub struct NbdNetlink {
    sock: File,
    family: u16,
}

impl NbdNetlink {
    /// Open a generic netlink socket and resolve the NBD family.
    pub fn open() -> Result<Self> {
        // Safe because the arguments are valid and the returned fd is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let mut nl = NbdNetlink {
            // Safe because `fd` is a valid file descriptor owned by nobody else.
            sock: unsafe { File::from_raw_fd(fd) },
            family: GENL_ID_CTRL,
        };
        let mut attrs = Attrs::default();
        attrs.put_str(CTRL_ATTR_FAMILY_NAME, NBD_GENL_FAMILY_NAME);
        let reply = nl
            .request(CTRL_CMD_GETFAMILY, 1, &attrs)?
            .unwrap_or_default();
        nl.family = Attrs::parse(&reply)
            .into_iter()
            .find(|(ty, _)| *ty == CTRL_ATTR_FAMILY_ID)
            .and_then(|(_, v)| Some(u16::from_ne_bytes(v.get(..2)?.try_into().ok()?)))
            .ok_or_else(|| enoent!("nbd_netlink: NBD generic netlink family not found"))?;
        Ok(nl)
    }

    /// Send a request and wait for its acknowledgment, returning the attributes of its reply.
    fn request(&mut self, cmd: u8, version: u8, attrs: &Attrs) -> Result<Option<Vec<u8>>> {
        // Messages written to a netlink socket go to the kernel.
        self.sock
            .write_all(&encode_request(self.family, cmd, version, attrs))?;
        let mut reply = None;
        let mut buf = vec![0u8; 32 << 10];
        loop {
            let n = match self.sock.read(&mut buf) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                res => res?,
            };
            if parse_replies(&buf[..n], &mut reply)? {
                return Ok(reply);
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
    ///
    /// The device stays in the pool of the nbd module once disconnected.
    pub fn connect(&mut self, cfg: &DeviceConfig, socks: &[RawFd]) -> Result<()> {
        let mut attrs = Self::device_attrs(cfg, socks);
        attrs
            .put_u64(NBD_ATTR_SIZE_BYTES, cfg.size_bytes)
            .put_u64(NBD_ATTR_BLOCK_SIZE_BYTES, cfg.block_size)
            .put_u64(NBD_ATTR_SERVER_FLAGS, cfg.server_flags);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn message(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut m = ((NLMSG_HDR_LEN + body.len()) as u32).to_ne_bytes().to_vec();
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn test_encode_request() {
        let mut attrs = Attrs::default();
        attrs
            .put_u32(NBD_ATTR_INDEX, 3)
            .put_str(NBD_ATTR_BACKEND_IDENTIFIER, "id");
        let msg = encode_request(0x20, NBD_CMD_CONNECT, 1, &attrs);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + GENL_HDR_LEN + 8 + 8);
        assert_eq!(&msg[0..4], &(msg.len() as u32).to_ne_bytes());
        assert_eq!(&msg[4..6], &0x20u16.to_ne_bytes());
        assert_eq!(&msg[16..18], &[NBD_CMD_CONNECT, 1]);
        assert_eq!(
            Attrs::parse(&msg[NLMSG_HDR_LEN + GENL_HDR_LEN..]),
            vec![
                (NBD_ATTR_INDEX, &3u32.to_ne_bytes()[..]),
                (NBD_ATTR_BACKEND_IDENTIFIER, &b"id\0"[..]),
            ]
        );
    }

    #[test]
    fn test_parse_replies() {
        let mut data = vec![NBD_CMD_CONNECT, 1, 0, 0];
        data.extend_from_slice(&Attrs::default().put_u32(NBD_ATTR_INDEX, 9).0);
        let ack = message(NLMSG_ERROR, &0i32.to_ne_bytes());
        /// Name, messages, length of the reply, and whether acknowledged, or the errno.
        type Test = (
            &'static str,
            Vec<u8>,
            Option<usize>,
            std::result::Result<bool, i32>,
        );
        let tests: Vec<Test> = vec![
            ("Ack", ack.clone(), None, Ok(true)),
            (
                "Error",
                message(NLMSG_ERROR, &(-libc::EBUSY).to_ne_bytes()),
                None,
                Err(libc::EBUSY),
            ),
            (
                "DataThenAck",
                [message(0x20, &data), ack.clone()].concat(),
                Some(data.len() - GENL_HDR_LEN),
                Ok(true),
            ),
            ("DataOnly", message(0x20, &data), Some(8), Ok(false)),
            ("Truncated", ack[..8].to_vec(), None, Ok(false)),
        ];
        for (name, buf, want_reply, want) in tests {
            let mut reply = None;
            match (parse_replies(&buf, &mut reply), want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{name}"),
                (Err(e), Err(code)) => assert_eq!(e.raw_os_error(), Some(code), "{name}"),
                (got, _) => panic!("{name}: {got:?}"),
            }
            assert_eq!(reply.map(|r| r.len()), want_reply, "{name}");
        }
    }
}
