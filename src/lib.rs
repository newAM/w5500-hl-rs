//! Platform agnostic rust driver for the [Wiznet W5500] internet offload chip.
//!
//! This crate contains higher level (hl) socket operations, built on-top of my
//! other crate, [w5500-ll], which contains register accessors, and networking
//! data types for the W5500.
//!
//! # Design
//!
//! There are no separate socket structures.
//! The [`Tcp`] and [`Udp`] traits provided in this crate simply extend the
//! [`Registers`] trait provided in [w5500-ll].
//! This makes for a less ergonomic API, but a much more portable API because
//! there are no mutexes or runtime checks to enable socket structures to share
//! ownership of the underlying W5500 device.
//!
//! You will likely want to wrap up the underlying structure that implements
//! the [`Registers`], [`Tcp`], and [`Udp`] traits to provide separate socket
//! structures utilizing whatever Mutex is available for your platform / RTOS.
//!
//! # Feature Flags
//!
//! All features are disabled by default.
//!
//! * `defmt`: Passthrough to [w5500-ll].
//! * `embedded-hal`: Passthrough to [w5500-ll].
//! * `std`: Passthrough to [w5500-ll].
//!
//! # Examples
//!
//! UDP sockets
//!
//! ```no_run
//! # use embedded_hal_mock as h;
//! # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
//! use w5500_hl::ll::{
//!     net::{Ipv4Addr, SocketAddrV4},
//!     Registers,
//!     Socket::Socket0,
//! };
//! use w5500_hl::Udp;
//!
//! // open Socket0 as a UDP socket on port 1234
//! w5500.udp_bind(Socket0, 1234)?;
//!
//! // send 4 bytes to 192.168.2.4:8080, and get the number of bytes transmitted
//! let data: [u8; 4] = [0, 1, 2, 3];
//! let destination = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 4), 8080);
//! let tx_bytes = w5500.udp_send_to(Socket0, &data, &destination);
//! # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
//! ```
//!
//! TCP streams (client)
//!
//! ```no_run
//! # use embedded_hal_mock as h;
//! # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
//! use w5500_hl::ll::{
//!     net::{Ipv4Addr, SocketAddrV4},
//!     Registers, Socket,
//! };
//! use w5500_hl::Tcp;
//!
//! const MQTT_SOCKET: Socket = Socket::Socket0;
//! const MQTT_SOURCE_PORT: u16 = 33650;
//! const MQTT_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 10), 1883);
//!
//! // initiate a TCP connection to a MQTT server
//! w5500.tcp_connect(MQTT_SOCKET, MQTT_SOURCE_PORT, &MQTT_SERVER)?;
//! # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
//! ```
//!
//! TCP listeners (server)
//!
//! ```no_run
//! # use embedded_hal_mock as h;
//! # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
//! use w5500_hl::ll::{
//!     net::{Ipv4Addr, SocketAddrV4},
//!     Registers, Socket,
//! };
//! use w5500_hl::Tcp;
//!
//! const HTTP_SOCKET: Socket = Socket::Socket1;
//! const HTTP_PORT: u16 = 80;
//!
//! // serve HTTP
//! w5500.tcp_listen(HTTP_SOCKET, HTTP_PORT)?;
//! # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
//! ```
//!
//! # Related Crates
//!
//! * [w5500-ll] - Low level W5500 register accessors.
//! * [w5500-regsim] - Register simulation using [`std::net`].
//!
//! [`Registers`]: https://docs.rs/w5500-ll/latest/w5500_ll/trait.Registers.html
//! [`std::net`]: https://doc.rust-lang.org/std/net/index.html
//! [w5500-ll]: https://github.com/newAM/w5500-ll-rs
//! [w5500-regsim]: https://github.com/newAM/w5500-regsim-rs
//! [Wiznet W5500]: https://www.wiznet.io/product-item/w5500/
//! [`Tcp`]: https://docs.rs/w5500-hl/0.3.0/w5500_hl/trait.Tcp.html
//! [`Udp`]: https://docs.rs/w5500-hl/0.3.0/w5500_hl/trait.Udp.html
#![doc(html_root_url = "https://docs.rs/w5500-hl/0.3.0")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

pub use w5500_ll as ll;

use ll::{Protocol, Registers, Socket, SocketCommand, SocketMode, SocketStatus, SOCKETS};

use core::cmp::min;
use core::convert::TryFrom;

/// Networking data types.
///
/// These are exported from [`w5500_ll::net`].
pub mod net {
    pub use w5500_ll::net::{Eui48Addr, Ipv4Addr, SocketAddrV4};
}

use net::{Ipv4Addr, SocketAddrV4};

// note: not your standard UDP datagram header
// For a UDP socket the W5500 UDP header contains:
// * 4 bytes origin IP
// * 2 bytes origin port
// * 2 bytes size
const UDP_HEADER_LEN: u16 = 8;
const UDP_HEADER_LEN_USIZE: usize = UDP_HEADER_LEN as usize;

/// Deserialize a UDP header.
const fn deser_hdr(buf: [u8; UDP_HEADER_LEN_USIZE]) -> (u16, SocketAddrV4) {
    (
        u16::from_be_bytes([buf[6], buf[7]]),
        SocketAddrV4::new(
            Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]),
            u16::from_be_bytes([buf[4], buf[5]]),
        ),
    )
}

fn port_is_unique<T: ?Sized, E>(w5500: &mut T, socket: Socket, port: u16) -> Result<bool, E>
where
    T: Registers<Error = E>,
{
    const CLOSED_STATUS: [Result<SocketStatus, u8>; 3] = [
        Ok(SocketStatus::Closed),
        Ok(SocketStatus::CloseWait),
        Ok(SocketStatus::Closing),
    ];
    for socket in SOCKETS.iter().filter(|s| s != &&socket) {
        if w5500.sn_port(*socket)? == port {
            let status = w5500.sn_sr(*socket)?;
            if !CLOSED_STATUS.iter().any(|x| x == &status) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// A W5500 UDP socket trait.
///
/// After creating a `UdpSocket` by [`bind`]ing it to a socket address,
/// data can be [sent to] and [received from] any other socket address.
///
/// As stated in the User Datagram Protocol's specification in [IETF RFC 768],
/// UDP is an unordered, unreliable protocol; refer to [`Tcp`] for the TCP trait.
///
/// # Comparison to [`std::net::UdpSocket`]
///
/// * Everything is non-blocking.
/// * There is no socket struct, you must pass a socket number as the first
///   argument to the methods.  This was simply the cleanest solution to the
///   ownership problem after some experimentation; though it certainly is not
///   the safest.
///
/// [`bind`]: Udp::udp_bind
/// [IETF RFC 768]: https://tools.ietf.org/html/rfc768
/// [received from]: Udp::udp_recv_from
/// [sent to]: Udp::udp_send_to
/// [`Tcp`]: crate::Tcp
/// [`std::net::UdpSocket`]: https://doc.rust-lang.org/std/net/struct.UdpSocket.html
pub trait Udp<E>: Registers<Error = E> {
    /// Binds the socket to the given port.
    ///
    /// This will close the socket, which will reset the RX and TX buffers.
    ///
    /// # Comparison to [`std::net::UdpSocket::bind`]
    ///
    /// This method accepts a port instead of a [`net::SocketAddrV4`], this is
    /// because the IP address is global for the device, set by the
    /// [source IP register], and cannot be set on a per-socket basis.
    ///
    /// Additionally you can only provide one port, instead of iterable
    /// addresses to bind.
    ///
    /// # Panics
    ///
    /// * (debug) The port must not be in use by any other socket on the W5500.
    ///
    /// # Example
    ///
    /// Bind the first socket to port 8080.
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::Udp;
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`std::net::UdpSocket::bind`]: https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.bind
    /// [source IP register]: w5500_ll::Registers::sipr
    fn udp_bind(&mut self, socket: Socket, port: u16) -> Result<(), E> {
        debug_assert!(
            port_is_unique(self, socket, port)?,
            "Local port {} is in use",
            port
        );

        self.set_sn_cr(socket, SocketCommand::Close)?;
        // This will not hang, the socket status will always change to closed
        // after a close command.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Closed) {
                break;
            }
        }
        self.set_sn_port(socket, port)?;
        let mut mode = SocketMode::default();
        mode.set_protocol(Protocol::Udp);
        self.set_sn_mr(socket, mode)?;
        self.set_sn_cr(socket, SocketCommand::Open)?;
        // This will not hang, the socket status will always change to Udp
        // after a open command with SN_MR set to UDP.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Udp) {
                break;
            }
        }
        Ok(())
    }

    /// Receives a single datagram message on the socket.
    /// On success, returns the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes.
    /// If a message is too long to fit in the supplied buffer, excess bytes
    /// will be discarded.
    ///
    /// # Comparison to [`std::net::UdpSocket::recv_from`]
    ///
    /// * This method will always discard excess bytes from the socket buffer.
    /// * This method is non-blocking, use [`nb::block`] to treat it as blocking.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use nb::block;
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     Udp,
    /// };
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let mut buf = [0; 10];
    /// let (number_of_bytes, src_addr) = block!(w5500.udp_recv_from(Socket0, &mut buf))?;
    ///
    /// // panics if bytes were discarded
    /// assert!(
    ///     number_of_bytes < buf.len(),
    ///     "Buffer was too small to receive all data"
    /// );
    ///
    /// let filled_buf = &mut buf[..number_of_bytes];
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`std::net::UdpSocket::recv_from`]: https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.recv_from
    fn udp_recv_from(
        &mut self,
        socket: Socket,
        buf: &mut [u8],
    ) -> nb::Result<(usize, SocketAddrV4), E> {
        let mut rsr: u16 = self.sn_rx_rsr(socket)?;

        // nothing to recieve
        if rsr < UDP_HEADER_LEN {
            return Err(nb::Error::WouldBlock);
        }

        debug_assert_eq!(self.sn_sr(socket)?, Ok(SocketStatus::Udp));

        let mut ptr: u16 = self.sn_rx_rd(socket)?;
        let mut header: [u8; UDP_HEADER_LEN_USIZE] = [0; UDP_HEADER_LEN_USIZE];
        self.sn_rx_buf(socket, ptr, &mut header)?;
        ptr = ptr.wrapping_add(UDP_HEADER_LEN);
        rsr -= UDP_HEADER_LEN;
        let (pkt_size, origin) = deser_hdr(header);

        // not all data as indicated by the header has been buffered
        if rsr < pkt_size {
            return Err(nb::Error::WouldBlock);
        }

        let read_size: usize = min(usize::from(pkt_size), buf.len());
        if read_size != 0 {
            self.sn_rx_buf(socket, ptr, &mut buf[..read_size])?;
        }
        ptr = ptr.wrapping_add(pkt_size);
        self.set_sn_rx_rd(socket, ptr)?;
        self.set_sn_cr(socket, SocketCommand::Recv)?;
        Ok((read_size, origin))
    }

    /// Receives a single datagram message on the socket, without removing it
    /// from the queue.
    /// On success, returns the number of bytes read and the origin.
    ///
    /// # Comparison to [`std::net::UdpSocket::peek_from`]
    ///
    /// * This method will never discard excess bytes from the socket buffer.
    /// * This method is non-blocking, use [`nb::block`] to treat it as blocking.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use nb::block;
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     Udp,
    /// };
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let mut buf = [0; 10];
    /// let (number_of_bytes, src_addr) = block!(w5500.udp_peek_from(Socket0, &mut buf))?;
    ///
    /// // panics if buffer was too small
    /// assert!(
    ///     number_of_bytes > buf.len(),
    ///     "Buffer was too small to receive all data"
    /// );
    ///
    /// let filled_buf = &mut buf[..number_of_bytes];
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`std::net::UdpSocket::peek_from`]: https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.peek_from
    fn udp_peek_from(
        &mut self,
        socket: Socket,
        buf: &mut [u8],
    ) -> nb::Result<(usize, SocketAddrV4), E> {
        let mut rsr: u16 = self.sn_rx_rsr(socket)?;

        // nothing to recieve
        if rsr < UDP_HEADER_LEN {
            return Err(nb::Error::WouldBlock);
        }

        debug_assert_eq!(self.sn_sr(socket)?, Ok(SocketStatus::Udp));

        let mut ptr: u16 = self.sn_rx_rd(socket)?;
        let mut header: [u8; UDP_HEADER_LEN_USIZE] = [0; UDP_HEADER_LEN_USIZE];
        self.sn_rx_buf(socket, ptr, &mut header)?;
        ptr = ptr.wrapping_add(UDP_HEADER_LEN);
        rsr -= UDP_HEADER_LEN;
        let (pkt_size, origin) = deser_hdr(header);

        // not all data as indicated by the header has been buffered
        if rsr < pkt_size {
            return Err(nb::Error::WouldBlock);
        }

        let read_size: usize = min(usize::from(pkt_size), buf.len());
        if read_size != 0 {
            self.sn_rx_buf(socket, ptr, &mut buf[..read_size])?;
        }

        Ok((read_size, origin))
    }

    /// Receives the origin and size of the next datagram avaliable on the
    /// socket, without removing it from the queue.
    ///
    /// There is no [`std::net`](https://doc.rust-lang.org/std/net) equivalent
    /// for this method.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use nb::block;
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     Udp,
    /// };
    /// // global_allocator is currently avaliable on nightly for embedded rust
    /// extern crate alloc;
    /// use alloc::vec::{self, Vec};
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let (bytes_to_allocate, _) = block!(w5500.udp_peek_from_header(Socket0))?;
    ///
    /// let mut buf: Vec<u8> = vec![0; bytes_to_allocate];
    /// let (number_of_bytes, source) = block!(w5500.udp_recv_from(Socket0, &mut buf))?;
    /// debug_assert_eq!(bytes_to_allocate, number_of_bytes);
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    fn udp_peek_from_header(&mut self, socket: Socket) -> nb::Result<(usize, SocketAddrV4), E> {
        let rsr: u16 = self.sn_rx_rsr(socket)?;

        // nothing to recieve
        if rsr < UDP_HEADER_LEN {
            return Err(nb::Error::WouldBlock);
        }

        debug_assert_eq!(self.sn_sr(socket)?, Ok(SocketStatus::Udp));

        let ptr: u16 = self.sn_rx_rd(socket)?;
        let mut header: [u8; UDP_HEADER_LEN_USIZE] = [0; UDP_HEADER_LEN_USIZE];
        self.sn_rx_buf(socket, ptr, &mut header)?;
        let (pkt_size, origin) = deser_hdr(header);
        Ok((usize::from(pkt_size), origin))
    }

    /// Sends data to the given address.
    /// On success, returns the number of bytes written.
    ///
    /// # Comparison to [`std::net::UdpSocket::send_to`]
    ///
    /// * You cannot transmit more than `u16::MAX` bytes at once.
    /// * You can only provide one destination.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Udp,
    /// };
    ///
    /// const DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8081);
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let buf: [u8; 10] = [0; 10];
    /// let tx_bytes = w5500.udp_send_to(Socket0, &buf, &DEST)?;
    /// assert_eq!(tx_bytes, buf.len());
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`std::net::UdpSocket::send_to`]: https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.send_to
    fn udp_send_to(&mut self, socket: Socket, buf: &[u8], addr: &SocketAddrV4) -> Result<usize, E> {
        self.set_sn_dest(socket, addr)?;
        self.udp_send(socket, buf)
    }

    /// Sends all data to the given address.
    ///
    /// Compared to [`udp_send_to`] this returns [`nb::Error::WouldBlock`] if
    /// there is not enough room in the transmit buffer for `buf`.
    ///
    /// If this method returns [`nb::Error::WouldBlock`] the socket destination
    /// will be set, and subsequent calls may use [`udp_send_all`] to attempt to
    /// send data to the same destination.
    ///
    /// If `buf` is larger than the configured socket buffer size this method
    /// will always return [`nb::Error::WouldBlock`].
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use nb::block;
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Udp,
    /// };
    ///
    /// const DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8081);
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let buf: [u8; 10] = [0; 10];
    /// block!(w5500.udp_send_all_to(Socket0, &buf, &DEST))?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`udp_send_all`]: Udp::udp_send_all
    fn udp_send_all_to(
        &mut self,
        socket: Socket,
        buf: &[u8],
        addr: &SocketAddrV4,
    ) -> nb::Result<(), E> {
        self.set_sn_dest(socket, addr)?;
        self.udp_send_all(socket, buf)
    }

    /// Sends data to the currently configured destination.
    ///
    /// The destination is set by the last call to [`set_sn_dest`],
    /// [`udp_send_to`], or [`udp_send_all_to`].
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Udp,
    /// };
    ///
    /// const DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8081);
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let buf: [u8; 10] = [0; 10];
    /// let tx_bytes = w5500.udp_send_to(Socket0, &buf, &DEST)?;
    /// assert_eq!(tx_bytes, buf.len());
    /// // send the same to the same destination
    /// let tx_bytes = w5500.udp_send(Socket0, &buf)?;
    /// assert_eq!(tx_bytes, buf.len());
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`set_sn_dest`]: w5500_ll::Registers::set_sn_dest
    /// [`udp_send_to`]: Udp::udp_send_to
    /// [`udp_send_all_to`]: Udp::udp_send_all_to
    /// [`udp_send`]: Udp::udp_send
    fn udp_send(&mut self, socket: Socket, buf: &[u8]) -> Result<usize, E> {
        debug_assert_eq!(self.sn_sr(socket)?, Ok(SocketStatus::Udp));

        let data_len: u16 = u16::try_from(buf.len()).unwrap_or(u16::MAX);
        let free_size: u16 = self.sn_tx_fsr(socket)?;
        let tx_bytes: u16 = min(data_len, free_size);
        if tx_bytes != 0 {
            let ptr: u16 = self.sn_tx_wr(socket)?;
            self.set_sn_tx_buf(socket, ptr, &buf[..usize::from(tx_bytes)])?;
            self.set_sn_tx_wr(socket, ptr.wrapping_add(tx_bytes))?;
            self.set_sn_cr(socket, SocketCommand::Send)?;
        }
        Ok(usize::from(tx_bytes))
    }

    /// Sends all data to the currently configured destination.
    ///
    /// Compared to [`udp_send`] this returns [`nb::Error::WouldBlock`] if
    /// there is not enough room in the transmit buffer for `buf`.
    ///
    /// The destination is set by the last call to [`set_sn_dest`],
    /// [`udp_send_to`], or [`udp_send_all_to`].
    ///
    /// If `buf` is larger than the configured socket buffer size this method
    /// will always return [`nb::Error::WouldBlock`].
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be opened as a UDP socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use nb::block;
    /// use w5500_hl::{
    ///     ll::{Registers, Socket::Socket0},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Udp,
    /// };
    ///
    /// const DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8081);
    ///
    /// w5500.set_sn_dest(Socket0, &DEST)?;
    /// w5500.udp_bind(Socket0, 8080)?;
    ///
    /// // send to the previously configured destination
    /// let buf: [u8; 10] = [0; 10];
    /// block!(w5500.udp_send_all(Socket0, &buf))?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`set_sn_dest`]: w5500_ll::Registers::set_sn_dest
    /// [`udp_send_to`]: Udp::udp_send_to
    /// [`udp_send_all_to`]: Udp::udp_send_all_to
    /// [`udp_send`]: Udp::udp_send
    fn udp_send_all(&mut self, socket: Socket, buf: &[u8]) -> nb::Result<(), E> {
        debug_assert_eq!(self.sn_sr(socket)?, Ok(SocketStatus::Udp));

        let free_size: u16 = self.sn_tx_fsr(socket)?;
        if usize::from(free_size) < buf.len() {
            return Err(nb::Error::WouldBlock);
        }

        let data_len: u16 = u16::try_from(buf.len()).unwrap_or(u16::MAX);
        let tx_bytes: u16 = min(data_len, free_size);
        if tx_bytes != 0 {
            let ptr: u16 = self.sn_tx_wr(socket)?;
            self.set_sn_tx_buf(socket, ptr, &buf[..usize::from(tx_bytes)])?;
            self.set_sn_tx_wr(socket, ptr.wrapping_add(tx_bytes))?;
            self.set_sn_cr(socket, SocketCommand::Send)?;
        }
        Ok(())
    }
}

/// Implement the UDP trait for any structure that implements [`w5500_ll::Registers`].
impl<T, E> Udp<E> for T where T: Registers<Error = E> {}

/// A W5500 TCP trait.
pub trait Tcp<E>: Registers<Error = E> {
    /// Starts the 3-way TCP handshake with the remote host.
    ///
    /// This method is used to create and interact with a TCP stream between
    /// a local host and a remote socket.
    ///
    /// After initiating a connection with [`tcp_connect`] and recieving the
    /// [`con`] interrupt data can be transmitting by using [`tcp_read`] and
    /// [`tcp_write`].
    ///
    /// Calling this method **does not** mean the socket will be connected
    /// afterwards, this simply starts the three way handshake.
    ///
    /// After calling this method you will eventually get one of 3 interrupts on
    /// the socket:
    ///
    /// 1. [`con`](w5500_ll::SocketInterrupt::con_raised)
    /// 2. [`discon`](w5500_ll::SocketInterrupt::discon_raised)
    /// 3. [`timeout`](w5500_ll::SocketInterrupt::timeout_raised)
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket number to use for this TCP stream.
    /// * `port` - The local port to use for the TCP connection.
    /// * `addr` - Address of the remote host to connect to.
    ///
    /// # Panics
    ///
    /// * (debug) The port must not be in use by any other socket on the W5500.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket, SocketInterrupt},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Tcp,
    /// };
    ///
    /// const MQTT_SOCKET: Socket = Socket::Socket0;
    /// const MQTT_SOURCE_PORT: u16 = 33650;
    /// const MQTT_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 10), 1883);
    ///
    /// w5500.tcp_connect(MQTT_SOCKET, MQTT_SOURCE_PORT, &MQTT_SERVER)?;
    ///
    /// // wait for a socket interrupt
    /// // you should use the actual interrupt pin, polling is just for demonstration
    /// loop {
    ///     let sn_ir: SocketInterrupt = w5500.sn_ir(MQTT_SOCKET)?;
    ///
    ///     // in reality you will want to handle disconnections gracefully with retries
    ///     assert!(!sn_ir.discon_raised());
    ///     assert!(!sn_ir.timeout_raised());
    ///
    ///     // connection succeded
    ///     if sn_ir.con_raised() {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`tcp_write`]: Tcp::tcp_write
    /// [`tcp_read`]: Tcp::tcp_read
    /// [`tcp_connect`]: Tcp::tcp_connect
    /// [`con`]: w5500_ll::SocketInterrupt::con_raised
    fn tcp_connect(&mut self, socket: Socket, port: u16, addr: &SocketAddrV4) -> Result<(), E> {
        debug_assert!(
            port_is_unique(self, socket, port)?,
            "Local port {} is in use",
            port
        );

        self.set_sn_cr(socket, SocketCommand::Close)?;
        // This will not hang, the socket status will always change to closed
        // after a close command.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Closed) {
                break;
            }
        }
        let mut mode = SocketMode::default();
        mode.set_protocol(Protocol::Tcp);
        self.set_sn_mr(socket, mode)?;
        self.set_sn_port(socket, port)?;
        self.set_sn_cr(socket, SocketCommand::Open)?;
        self.set_sn_dest(socket, addr)?;
        // This will not hang, the socket status will always change to Init
        // after a open command with SN_MR set to TCP.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Init) {
                break;
            }
        }
        self.set_sn_cr(socket, SocketCommand::Connect)
    }

    /// Open a TCP listener on the given port.
    ///
    /// After opening a listener with [`tcp_listen`] and recieving the
    /// [`con`] interrupt data can be transmitting by using [`tcp_read`] and
    /// [`tcp_write`].
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket number to use for this TCP listener.
    /// * `port` - The local port to listen for remote connections on.
    ///
    /// # Panics
    ///
    /// * (debug) The port must not be in use by any other socket on the W5500.
    ///
    /// # Example
    ///
    /// Create an HTTP server.
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket, SocketInterrupt},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Tcp,
    /// };
    /// // global_allocator is currently avaliable on nightly for embedded rust
    /// extern crate alloc;
    /// use alloc::vec::{self, Vec};
    ///
    /// const HTTP_SOCKET: Socket = Socket::Socket1;
    /// const HTTP_PORT: u16 = 80;
    ///
    /// // start serving
    /// w5500.tcp_listen(HTTP_SOCKET, HTTP_PORT)?;
    ///
    /// // wait for the RECV interrupt, indicating there is data to read from a client
    /// loop {
    ///     let sn_ir = w5500.sn_ir(HTTP_SOCKET).unwrap();
    ///     if sn_ir.recv_raised() {
    ///         w5500.set_sn_ir(HTTP_SOCKET, sn_ir).unwrap();
    ///         break;
    ///     }
    ///     if sn_ir.discon_raised() | sn_ir.timeout_raised() {
    ///         panic!("Socket disconnected while waiting for RECV");
    ///     }
    /// }
    ///
    /// let mut buf: Vec<u8> = vec![0; 256];
    /// let rx_bytes: usize = w5500.tcp_read(HTTP_SOCKET, &mut buf).unwrap();
    /// // Truncate the buffer to the number of bytes read
    /// // Safety: BUF is only borrowed mutably in one location
    /// let filled_buf: &[u8] = &buf[..rx_bytes];
    ///
    /// // parse HTTP request here using filled_buf
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`tcp_write`]: Tcp::tcp_write
    /// [`tcp_read`]: Tcp::tcp_read
    /// [`tcp_listen`]: Tcp::tcp_listen
    /// [`con`]: w5500_ll::SocketInterrupt::con_raised
    fn tcp_listen(&mut self, socket: Socket, port: u16) -> Result<(), E> {
        debug_assert!(
            port_is_unique(self, socket, port)?,
            "Local port {} is in use",
            port
        );

        self.set_sn_cr(socket, SocketCommand::Close)?;
        // This will not hang, the socket status will always change to closed
        // after a close command.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Closed) {
                break;
            }
        }
        let mut mode = SocketMode::default();
        mode.set_protocol(Protocol::Tcp);
        self.set_sn_mr(socket, mode)?;
        self.set_sn_port(socket, port)?;
        self.set_sn_cr(socket, SocketCommand::Open)?;
        // This will not hang, the socket status will always change to Init
        // after a open command with SN_MR set to TCP.
        // (unless you do somthing silly like holding the W5500 in reset)
        loop {
            if self.sn_sr(socket)? == Ok(SocketStatus::Init) {
                break;
            }
        }
        self.set_sn_cr(socket, SocketCommand::Listen)
    }

    /// Read data from the remote host, returning the number of bytes read.
    ///
    /// You should wait for the socket [`recv`] interrupt before calling this method.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be an [`Established`] TCP socket.
    ///
    /// # Example
    ///
    /// Send a MQTT CONNECT packet and read a CONNACK.
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket, SocketInterrupt},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Tcp,
    /// };
    ///
    /// const MQTT_SOCKET: Socket = Socket::Socket0;
    /// const MQTT_SOURCE_PORT: u16 = 33650;
    /// const MQTT_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 10), 1883);
    ///
    /// w5500.tcp_connect(MQTT_SOCKET, MQTT_SOURCE_PORT, &MQTT_SERVER)?;
    ///
    /// // ... wait for a CON interrupt
    ///
    /// const CONNECT: [u8; 14] = [
    ///     0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x0E, 0x10, 0x00, 0x00,
    /// ];
    /// let tx_bytes: usize = w5500.tcp_write(MQTT_SOCKET, &CONNECT)?;
    /// assert_eq!(tx_bytes, CONNECT.len());
    ///
    /// // ... wait for a RECV interrupt
    ///
    /// let mut buf = [0; 10];
    /// let rx_bytes: usize = w5500.tcp_read(MQTT_SOCKET, &mut buf)?;
    /// let filled_buf = &buf[..rx_bytes];
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`Established`]: w5500_ll::SocketStatus::Established
    /// [`recv`]: w5500_ll::SocketInterrupt::recv_raised
    fn tcp_read(&mut self, socket: Socket, buf: &mut [u8]) -> Result<usize, E> {
        debug_assert!(!matches!(
            self.sn_sr(socket)?,
            Ok(SocketStatus::Udp) | Ok(SocketStatus::Init) | Ok(SocketStatus::Macraw)
        ));

        let rx_bytes: u16 = {
            let rsr: u16 = self.sn_rx_rsr(socket)?;
            min(rsr, u16::try_from(buf.len()).unwrap_or(u16::MAX))
        };
        if rx_bytes != 0 {
            let ptr: u16 = self.sn_rx_rd(socket)?;
            self.sn_rx_buf(socket, ptr, &mut buf[..usize::from(rx_bytes)])?;
            self.set_sn_rx_rd(socket, ptr.wrapping_add(rx_bytes))?;
            self.set_sn_cr(socket, SocketCommand::Recv)?;
        }
        Ok(usize::from(rx_bytes))
    }

    /// Send data to the remote host, returning the number of bytes written.
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be an [`Established`] TCP socket.
    ///
    /// # Example
    ///
    /// Send a MQTT CONNECT packet.
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket, SocketInterrupt},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Tcp,
    /// };
    ///
    /// const MQTT_SOCKET: Socket = Socket::Socket0;
    /// const MQTT_SOURCE_PORT: u16 = 33650;
    /// const MQTT_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 10), 1883);
    ///
    /// w5500.tcp_connect(MQTT_SOCKET, MQTT_SOURCE_PORT, &MQTT_SERVER)?;
    ///
    /// // ... wait for a CON interrupt
    ///
    /// const CONNECT: [u8; 14] = [
    ///     0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x0E, 0x10, 0x00, 0x00,
    /// ];
    /// let tx_bytes: usize = w5500.tcp_write(MQTT_SOCKET, &CONNECT)?;
    /// assert_eq!(tx_bytes, CONNECT.len());
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`Established`]: w5500_ll::SocketStatus::Established
    fn tcp_write(&mut self, socket: Socket, buf: &[u8]) -> Result<usize, E> {
        debug_assert!(!matches!(
            self.sn_sr(socket)?,
            Ok(SocketStatus::Udp) | Ok(SocketStatus::Init) | Ok(SocketStatus::Macraw)
        ));

        let tx_bytes: u16 = {
            let data_len: u16 = u16::try_from(buf.len()).unwrap_or(u16::MAX);
            let free_size: u16 = self.sn_tx_fsr(socket)?;
            min(data_len, free_size)
        };
        if tx_bytes != 0 {
            let ptr: u16 = self.sn_tx_wr(socket)?;
            self.set_sn_tx_buf(socket, ptr, &buf[..usize::from(tx_bytes)])?;
            self.set_sn_tx_wr(socket, ptr.wrapping_add(tx_bytes))?;
            self.set_sn_cr(socket, SocketCommand::Send)?;
        }
        Ok(usize::from(tx_bytes))
    }

    /// Disconnect from the peer.
    ///
    /// If the disconnect is successful (FIN/ACK packet is received) the socket
    /// status changes to [`Closed`], otherwise TCP<sub>TO</sub> occurs, the
    /// [timeout interrupt] is raised, and the socket status changes to
    /// [`Closed`].
    ///
    /// # Panics
    ///
    /// * (debug) The socket must be an [`Established`] TCP socket.
    ///
    /// # Example
    ///
    /// Connect and disconnect from a MQTT server.
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::{
    ///     ll::{Registers, Socket, SocketInterrupt},
    ///     net::{Ipv4Addr, SocketAddrV4},
    ///     Tcp,
    /// };
    ///
    /// const MQTT_SOCKET: Socket = Socket::Socket0;
    /// const MQTT_SOURCE_PORT: u16 = 33650;
    /// const MQTT_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 10), 1883);
    ///
    /// w5500.tcp_connect(MQTT_SOCKET, MQTT_SOURCE_PORT, &MQTT_SERVER)?;
    ///
    /// // ... wait for a CON interrupt
    ///
    /// w5500.tcp_disconnect(MQTT_SOCKET)?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [`Closed`]: w5500_ll::SocketStatus::Closed
    /// [`Established`]: w5500_ll::SocketStatus::Established
    /// [timeout interrupt]: w5500_ll::SocketInterrupt::timeout_raised
    fn tcp_disconnect(&mut self, socket: Socket) -> Result<(), E> {
        debug_assert!(!matches!(
            self.sn_sr(socket)?,
            Ok(SocketStatus::Udp) | Ok(SocketStatus::Init) | Ok(SocketStatus::Macraw)
        ));
        self.set_sn_cr(socket, SocketCommand::Disconnect)
    }
}

/// Implement the TCP trait for any structure that implements [`w5500_ll::Registers`].
impl<T, E> Tcp<E> for T where T: Registers<Error = E> {}

/// Methods common to all W5500 socket types.
pub trait Common<E>: Registers<Error = E> {
    /// Returns the socket address.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::{Common, Udp};
    ///
    /// w5500.udp_bind(Socket0, 8080)?;
    /// let local_addr = w5500.local_addr(Socket0)?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    fn local_addr(&mut self, socket: Socket) -> Result<SocketAddrV4, E> {
        let ip: Ipv4Addr = self.sipr()?;
        let port: u16 = self.sn_port(socket)?;
        Ok(SocketAddrV4::new(ip, port))
    }

    /// Close a socket.
    ///
    /// This will not poll for completion, the socket may not be closed after
    /// this method has returned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::Common;
    ///
    /// w5500.close(Socket0)?;
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    fn close(&mut self, socket: Socket) -> Result<(), E> {
        self.set_sn_cr(socket, SocketCommand::Close)
    }

    /// Returns `true` if the socket state is [Closed].
    ///
    /// **Note:** This does not include states that indicate the socket is about
    /// to close, such as [Closing].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::{Common, Udp};
    ///
    /// w5500.close(Socket0)?;
    /// assert!(w5500.is_state_closed(Socket0)?);
    /// w5500.udp_bind(Socket0, 8080)?;
    /// assert!(!w5500.is_state_closed(Socket0)?);
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [Closed]: w5500_ll::SocketStatus::Closed
    /// [Closing]: w5500_ll::SocketStatus::Closing
    fn is_state_closed(&mut self, socket: Socket) -> Result<bool, E> {
        Ok(self.sn_sr(socket)? == Ok(SocketStatus::Closed))
    }

    /// Returns `true` if the socket state is any valid TCP state as described
    /// in [RFC 793].
    ///
    /// Valid TCP states include:
    ///
    /// * [Closed]
    /// * [Listen]
    /// * [SynSent]
    /// * [SynRecv]
    /// * [Established]
    /// * [FinWait]
    /// * [Closing]
    /// * [CloseWait]
    /// * [TimeWait]
    /// * [LastAck]
    ///
    /// **Note:** This **does not** include the W5500 [Init] state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::{Common, Udp};
    ///
    /// w5500.close(Socket0)?;
    /// assert!(w5500.is_state_tcp(Socket0)?);
    /// w5500.udp_bind(Socket0, 8080)?;
    /// assert!(!w5500.is_state_tcp(Socket0)?);
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [RFC 793]: https://tools.ietf.org/html/rfc793
    /// [Init]: w5500_ll::SocketStatus::Init
    /// [Closed]: w5500_ll::SocketStatus::Closed
    /// [Listen]: w5500_ll::SocketStatus::Listen
    /// [SynSent]: w5500_ll::SocketStatus::SynSent
    /// [SynRecv]: w5500_ll::SocketStatus::SynRecv
    /// [Established]: w5500_ll::SocketStatus::Established
    /// [FinWait]: w5500_ll::SocketStatus::FinWait
    /// [Closing]: w5500_ll::SocketStatus::Closing
    /// [CloseWait]: w5500_ll::SocketStatus::CloseWait
    /// [TimeWait]: w5500_ll::SocketStatus::TimeWait
    /// [LastAck]: w5500_ll::SocketStatus::LastAck
    fn is_state_tcp(&mut self, socket: Socket) -> Result<bool, E> {
        // Hopefully the compiler will optimize this to check that the state is
        // not MACRAW, UDP, or INIT.
        // Leaving it as-is since the code is more readable this way.
        Ok(matches!(
            self.sn_sr(socket)?,
            Ok(SocketStatus::Closed)
                | Ok(SocketStatus::Listen)
                | Ok(SocketStatus::SynSent)
                | Ok(SocketStatus::SynRecv)
                | Ok(SocketStatus::Established)
                | Ok(SocketStatus::FinWait)
                | Ok(SocketStatus::Closing)
                | Ok(SocketStatus::CloseWait)
                | Ok(SocketStatus::TimeWait)
                | Ok(SocketStatus::LastAck)
        ))
    }

    /// Returns `true` if the socket state is [Udp].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use embedded_hal_mock as h;
    /// # let mut w5500 = w5500_ll::blocking::vdm::W5500::new(h::spi::Mock::new(&[]), h::pin::Mock::new(&[]));
    /// use w5500_hl::ll::{Registers, Socket::Socket0};
    /// use w5500_hl::{Common, Udp};
    ///
    /// w5500.close(Socket0)?;
    /// assert!(!w5500.is_state_udp(Socket0)?);
    /// w5500.udp_bind(Socket0, 8080)?;
    /// assert!(w5500.is_state_udp(Socket0)?);
    /// # Ok::<(), w5500_hl::ll::blocking::vdm::Error<_, _>>(())
    /// ```
    ///
    /// [Udp]: w5500_ll::SocketStatus::Udp
    fn is_state_udp(&mut self, socket: Socket) -> Result<bool, E> {
        Ok(self.sn_sr(socket)? == Ok(SocketStatus::Udp))
    }
}

/// Implement the common socket trait for any structure that implements [`w5500_ll::Registers`].
impl<T, E> Common<E> for T where T: Registers<Error = E> {}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;

    struct MockRegisters {
        pub socket_ports: [u16; SOCKETS.len()],
        pub socket_status: [SocketStatus; SOCKETS.len()],
    }

    impl Registers for MockRegisters {
        type Error = Infallible;

        fn read(&mut self, _address: u16, _block: u8, _data: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn write(&mut self, _address: u16, _block: u8, _data: &[u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn sn_port(&mut self, socket: Socket) -> Result<u16, Self::Error> {
            Ok(self.socket_ports[usize::from(socket)])
        }

        fn sn_sr(&mut self, socket: Socket) -> Result<Result<SocketStatus, u8>, Self::Error> {
            Ok(Ok(self.socket_status[usize::from(socket)]))
        }
    }

    #[test]
    fn test_port_is_unique() {
        let mut mock = MockRegisters {
            socket_ports: [0; SOCKETS.len()],
            socket_status: [SocketStatus::Closed; SOCKETS.len()],
        };
        // basics
        assert!(port_is_unique(&mut mock, Socket::Socket0, 0).unwrap());
        assert!(port_is_unique(&mut mock, Socket::Socket0, 1).unwrap());
        assert!(port_is_unique(&mut mock, Socket::Socket0, u16::MAX).unwrap());

        // do not check our own socket
        mock.socket_status[0] = SocketStatus::Init;
        assert!(port_is_unique(&mut mock, Socket::Socket0, 0).unwrap());

        // other socket on other port
        assert!(port_is_unique(&mut mock, Socket::Socket0, 1).unwrap());

        // other socket on same port
        assert!(!port_is_unique(&mut mock, Socket::Socket1, 0).unwrap());
    }
}
