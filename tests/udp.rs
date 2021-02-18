use std::convert::{Infallible, TryFrom};
use w5500_hl::net::{Ipv4Addr, SocketAddrV4};
use w5500_hl::Udp;
use w5500_ll::{Protocol, Registers, Socket, SocketCommand, SocketMode, SocketStatus};

/// Tests debug asserts that ensure the socket is opened as UDP.
mod socket_status_debug_assert {
    use super::*;

    struct MockRegisters {}

    impl Registers for MockRegisters {
        type Error = Infallible;

        fn sn_rx_rsr(&mut self, _socket: Socket) -> Result<u16, Self::Error> {
            Ok(1024)
        }

        fn sn_sr(&mut self, _socket: Socket) -> Result<Result<SocketStatus, u8>, Self::Error> {
            Ok(SocketStatus::try_from(u8::from(SocketStatus::Closed)))
        }

        fn read(&mut self, _address: u16, _block: u8, _data: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn write(&mut self, _address: u16, _block: u8, _data: &[u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }

    #[test]
    #[should_panic]
    fn udp_recv_from() {
        let mut test = MockRegisters {};
        let mut buf: [u8; 1] = [0];
        test.udp_recv_from(Socket::Socket0, &mut buf).ok();
    }

    #[test]
    #[should_panic]
    fn udp_peek_from() {
        let mut test = MockRegisters {};
        let mut buf: [u8; 1] = [0];
        test.udp_peek_from(Socket::Socket0, &mut buf).ok();
    }

    #[test]
    #[should_panic]
    fn udp_peek_from_header() {
        let mut test = MockRegisters {};
        test.udp_peek_from_header(Socket::Socket0).ok();
    }

    #[test]
    #[should_panic]
    fn udp_send_to() {
        let mut test = MockRegisters {};
        let buf: [u8; 1] = [0];
        test.udp_send_to(
            Socket::Socket0,
            &buf,
            &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        )
        .ok();
    }

    #[test]
    #[should_panic]
    fn udp_send() {
        let mut test = MockRegisters {};
        let buf: [u8; 1] = [0];
        test.udp_send(Socket::Socket0, &buf).ok();
    }
}

/// Tests blocking UDP functions return nb::Error::WouldBlock when there is no
/// header in the RX buffer.
mod would_block_header {
    use super::*;

    struct MockRegisters {}

    impl Registers for MockRegisters {
        type Error = Infallible;

        fn sn_rx_rsr(&mut self, _socket: Socket) -> Result<u16, Self::Error> {
            Ok(5)
        }

        fn read(&mut self, _address: u16, _block: u8, _data: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn write(&mut self, _address: u16, _block: u8, _data: &[u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }

    #[test]
    fn udp_peek_from() {
        let mut mock = MockRegisters {};
        let mut buf: [u8; 1] = [0];
        assert_eq!(
            mock.udp_peek_from(Socket::Socket0, &mut buf),
            Err(nb::Error::WouldBlock)
        );
    }

    #[test]
    fn udp_peek_from_header() {
        let mut mock = MockRegisters {};
        assert_eq!(
            mock.udp_peek_from_header(Socket::Socket0),
            Err(nb::Error::WouldBlock)
        );
    }

    #[test]
    fn udp_recv_from() {
        let mut mock = MockRegisters {};
        let mut buf: [u8; 1] = [0];
        assert_eq!(
            mock.udp_recv_from(Socket::Socket0, &mut buf),
            Err(nb::Error::WouldBlock)
        );
    }
}

/// Tests `send_all` UDP functions return nb::Error::WouldBlock if there is not
/// enough room in the transmit buffer for all data.
mod would_block_send_all {
    use super::*;

    const SOCKET: Socket = Socket::Socket4;
    const DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 0), 8082);

    struct MockRegisters {
        dest: Vec<SocketAddrV4>,
        fsr: u16,
    }

    impl Registers for MockRegisters {
        type Error = Infallible;

        fn set_sn_dest(&mut self, socket: Socket, addr: &SocketAddrV4) -> Result<(), Self::Error> {
            assert_eq!(socket, SOCKET);
            let expected = self.dest.pop().expect("Unexpected call to set_sn_dest");
            assert_eq!(&expected, addr);
            Ok(())
        }

        fn sn_tx_fsr(&mut self, socket: Socket) -> Result<u16, Self::Error> {
            assert_eq!(socket, SOCKET);
            Ok(self.fsr)
        }

        fn sn_sr(&mut self, socket: Socket) -> Result<Result<SocketStatus, u8>, Self::Error> {
            assert_eq!(socket, SOCKET);
            Ok(Ok(SocketStatus::Udp))
        }

        fn read(&mut self, _address: u16, _block: u8, _data: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn write(&mut self, _address: u16, _block: u8, _data: &[u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }

    #[test]
    fn fsr_zero() {
        let buf: [u8; 1] = [0];

        let mut mock = MockRegisters {
            dest: vec![],
            fsr: 0,
        };
        assert_eq!(mock.udp_send_all(SOCKET, &buf), Err(nb::Error::WouldBlock));

        let mut mock = MockRegisters {
            dest: vec![DEST],
            fsr: 0,
        };
        assert_eq!(
            mock.udp_send_all_to(SOCKET, &buf, &DEST),
            Err(nb::Error::WouldBlock)
        );
        assert!(mock.dest.is_empty());
    }

    #[test]
    fn never_block() {
        let buf: [u8; 0] = [];

        let mut mock = MockRegisters {
            dest: vec![],
            fsr: 0,
        };
        mock.udp_send_all(SOCKET, &buf).unwrap();

        let mut mock = MockRegisters {
            dest: vec![DEST],
            fsr: 0,
        };
        mock.udp_send_all_to(SOCKET, &buf, &DEST).unwrap();
        assert!(mock.dest.is_empty());
    }

    #[test]
    fn always_block() {
        let buf: [u8; 2049] = [0; 2049];
        const FSR: u16 = 2048;

        let mut mock = MockRegisters {
            dest: vec![],
            fsr: FSR,
        };
        assert_eq!(mock.udp_send_all(SOCKET, &buf), Err(nb::Error::WouldBlock));

        let mut mock = MockRegisters {
            dest: vec![DEST],
            fsr: FSR,
        };
        assert_eq!(
            mock.udp_send_all_to(SOCKET, &buf, &DEST),
            Err(nb::Error::WouldBlock)
        );
        assert!(mock.dest.is_empty());
    }
}

/// Tests the udp_bind method
mod bind {
    use super::*;

    const TEST_SOCKET: Socket = Socket::Socket7;
    const TEST_PORT: u16 = 0xABCD;

    struct MockRegisters {
        sn_sr: Vec<u8>,
        sn_cr: Vec<SocketCommand>,
    }

    impl Registers for MockRegisters {
        type Error = Infallible;

        fn set_sn_cr(&mut self, socket: Socket, cmd: SocketCommand) -> Result<(), Self::Error> {
            assert_eq!(socket, TEST_SOCKET);
            assert_eq!(cmd, self.sn_cr.pop().expect("Unexpected socket command"));
            Ok(())
        }

        fn set_sn_port(&mut self, socket: Socket, port: u16) -> Result<(), Self::Error> {
            assert_eq!(socket, TEST_SOCKET);
            assert_eq!(port, TEST_PORT);
            Ok(())
        }

        fn set_sn_mr(&mut self, socket: Socket, mode: SocketMode) -> Result<(), Self::Error> {
            assert_eq!(socket, TEST_SOCKET);
            assert_eq!(mode.protocol(), Ok(Protocol::Udp));
            Ok(())
        }

        fn sn_sr(&mut self, socket: Socket) -> Result<Result<SocketStatus, u8>, Self::Error> {
            assert_eq!(socket, TEST_SOCKET);
            Ok(SocketStatus::try_from(
                self.sn_sr.pop().expect("Unexpected socket status read"),
            ))
        }

        fn sn_port(&mut self, socket: Socket) -> Result<u16, Self::Error> {
            Ok(u16::from(u8::from(socket)))
        }

        fn read(&mut self, _address: u16, _block: u8, _data: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn write(&mut self, _address: u16, _block: u8, _data: &[u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }

    #[test]
    fn udp_bind() {
        let mut mock = MockRegisters {
            sn_sr: vec![
                SocketStatus::Udp.into(),
                0xFE,
                SocketStatus::Established.into(),
                SocketStatus::Closed.into(),
                0xFF,
                SocketStatus::Init.into(),
            ],
            sn_cr: vec![SocketCommand::Open, SocketCommand::Close],
        };
        mock.udp_bind(TEST_SOCKET, TEST_PORT).unwrap();
    }
}
