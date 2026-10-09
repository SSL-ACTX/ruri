use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Query mDNS for `_adb-tls-connect._tcp.local` and extract the advertised port from the SRV record.
/// Returns immediately upon finding a valid adb port, or `None` if the timeout expires.
pub fn discover_adbd_mdns(timeout: Duration) -> Option<u16> {
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let socket = UdpSocket::bind(bind_addr).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_multicast_loop_v4(true).ok()?;

    // Multicast address for mDNS
    let mdns_multicast = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

    // Build DNS query packet:
    // Header: ID=0, Flags=0 (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    // QNAME: \x10_adb-tls-connect\x04_tcp\x05local\x00
    for label in ["_adb-tls-connect", "_tcp", "local"] {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);

    // QTYPE: PTR (12), QCLASS: IN (1)
    packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

    if socket.send_to(&packet, mdns_multicast).is_err() {
        return None;
    }

    let mut buf = [0u8; 4096];
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        let (len, _) = match socket.recv_from(&mut buf) {
            Ok(res) => res,
            Err(_) => break,
        };

        if let Some(port) = parse_adbd_srv_port(&buf[..len]) {
            return Some(port);
        }
    }

    None
}

/// Parse DNS response bytes and search for SRV records (Type 33 / 0x0021)
fn parse_adbd_srv_port(data: &[u8]) -> Option<u16> {
    // Basic verification: must have at least DNS header (12 bytes)
    if data.len() < 12 {
        return None;
    }

    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    let ns_count = u16::from_be_bytes([data[8], data[9]]) as usize;
    let ar_count = u16::from_be_bytes([data[10], data[11]]) as usize;

    let total_records = an_count + ns_count + ar_count;
    if total_records == 0 {
        return None;
    }

    // Skip Question section
    let mut offset = 12;
    for _ in 0..qd_count {
        offset = skip_name(data, offset)?;
        if offset + 4 > data.len() {
            return None;
        }
        offset += 4; // QTYPE (2) + QCLASS (2)
    }

    // Parse Resource Records
    for _ in 0..total_records {
        if offset >= data.len() {
            break;
        }
        offset = skip_name(data, offset)?;
        if offset + 10 > data.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass =
            u16::from_be_bytes([data[offset + 2], data[offset + 3]]) & 0x7FFF;
        // TTL: 4 bytes (offset + 4 .. offset + 8)
        let rdlength =
            u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            return None;
        }

        // SRV Record Type = 33 (0x0021)
        // RDATA format: Priority (2), Weight (2), Port (2), Target (...)
        if rtype == 33 && rdlength >= 6 {
            let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            if port > 0 {
                return Some(port);
            }
        }

        offset += rdlength;
    }

    None
}

/// Helper to step past DNS names (with compression pointer handling)
fn skip_name(data: &[u8], mut offset: usize) -> Option<usize> {
    while offset < data.len() {
        let b = data[offset];
        if b == 0 {
            return Some(offset + 1);
        } else if (b & 0xC0) == 0xC0 {
            // Pointer (2 bytes)
            return Some(offset + 2);
        } else {
            // Normal label
            let len = b as usize;
            offset += 1 + len;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_srv_record() {
        // Mock DNS response packet containing an SRV record
        let mock_pkt = vec![
            0x00, 0x00, 0x84, 0x00, // ID=0, Flags
            0x00, 0x00, // QDCOUNT=0
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // NAME: pointer to root or 0
            0x00, // TYPE: SRV (33)
            0x00, 0x21, // CLASS: IN (1)
            0x00, 0x01, // TTL: 120
            0x00, 0x00, 0x00, 0x78, // RDLENGTH: 8
            0x00, 0x08,
            // RDATA: Priority=0, Weight=0, Port=37193 (0x9149), Target=0
            0x00, 0x00, 0x00, 0x00, 0x91, 0x49, 0x00, 0x00,
        ];

        let port = parse_adbd_srv_port(&mock_pkt);
        assert_eq!(port, Some(37193));
    }
}
