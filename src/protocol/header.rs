pub const A_SYNC: u32 = 0x434e5953; // "SYNC"
pub const A_CNXN: u32 = 0x4e584e43; // "CNXN"
pub const A_AUTH: u32 = 0x48545541; // "AUTH"
pub const A_OPEN: u32 = 0x4e45504f; // "OPEN"
pub const A_OKAY: u32 = 0x59414b4f; // "OKAY"
pub const A_CLSE: u32 = 0x45534c43; // "CLSE"
pub const A_WRTE: u32 = 0x45545257; // "WRTE"
pub const A_STLS: u32 = 0x534c5453; // "STLS" (Android 11+ TLS upgrade)

pub const ADB_VERSION: u32 = 0x01000000;
pub const ADB_MAX_PAYLOAD: u32 = 1024 * 1024; // 1 MB

pub const AUTH_TYPE_TOKEN: u32 = 1;
pub const AUTH_TYPE_SIGNATURE: u32 = 2;
pub const AUTH_TYPE_RSAPUBLICKEY: u32 = 3;

pub const STLS_VERSION: u32 = 0x01000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AdbHeader {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_crc32: u32,
    pub magic: u32,
}

impl AdbHeader {
    pub const SIZE: usize = 24;

    pub fn new(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Self {
        let data_length = payload.len() as u32;
        let data_crc32 = calculate_checksum(payload);
        let magic = command ^ 0xFFFF_FFFF;

        Self {
            command,
            arg0,
            arg1,
            data_length,
            data_crc32,
            magic,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.command.to_le_bytes());
        buf[4..8].copy_from_slice(&self.arg0.to_le_bytes());
        buf[8..12].copy_from_slice(&self.arg1.to_le_bytes());
        buf[12..16].copy_from_slice(&self.data_length.to_le_bytes());
        buf[16..20].copy_from_slice(&self.data_crc32.to_le_bytes());
        buf[20..24].copy_from_slice(&self.magic.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, &'static str> {
        let command = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let arg0 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let arg1 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let data_length = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let data_crc32 = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let magic = u32::from_le_bytes(bytes[20..24].try_into().unwrap());

        if (command ^ 0xFFFF_FFFF) != magic {
            return Err("Invalid packet magic header");
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_crc32,
            magic,
        })
    }

    pub fn command_name(&self) -> &'static str {
        match self.command {
            A_SYNC => "SYNC",
            A_CNXN => "CNXN",
            A_AUTH => "AUTH",
            A_OPEN => "OPEN",
            A_OKAY => "OKAY",
            A_CLSE => "CLSE",
            A_WRTE => "WRTE",
            A_STLS => "STLS",
            _ => "UNKNOWN",
        }
    }
}

pub fn calculate_checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_pack_unpack() {
        let payload = b"host::ruri";
        let header = AdbHeader::new(A_CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, payload);
        let bytes = header.to_bytes();
        let unpacked = AdbHeader::from_bytes(&bytes).expect("unpack failed");
        assert_eq!(header, unpacked);
        assert_eq!(unpacked.command_name(), "CNXN");
        assert_eq!(unpacked.data_length, payload.len() as u32);
        assert_eq!(unpacked.data_crc32, calculate_checksum(payload));
    }
}
