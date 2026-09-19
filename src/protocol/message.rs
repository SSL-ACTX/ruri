use super::header::{
    A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_STLS, A_WRTE, ADB_MAX_PAYLOAD, ADB_VERSION,
    AdbHeader, STLS_VERSION,
};
use std::io::{self, Read, Write};

#[derive(Debug, Clone)]
pub struct AdbMessage {
    pub header: AdbHeader,
    pub payload: Vec<u8>,
}

impl AdbMessage {
    pub fn new(command: u32, arg0: u32, arg1: u32, payload: Vec<u8>) -> Self {
        let header = AdbHeader::new(command, arg0, arg1, &payload);
        Self { header, payload }
    }

    pub fn cnxn(banner: &str) -> Self {
        let payload = banner.as_bytes().to_vec();
        Self::new(A_CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, payload)
    }

    pub fn stls() -> Self {
        Self::new(A_STLS, STLS_VERSION, 0, Vec::new())
    }

    pub fn open(local_id: u32, destination: &str) -> Self {
        let mut payload = destination.as_bytes().to_vec();
        payload.push(0);
        Self::new(A_OPEN, local_id, 0, payload)
    }

    pub fn okay(local_id: u32, remote_id: u32) -> Self {
        Self::new(A_OKAY, local_id, remote_id, Vec::new())
    }

    pub fn clse(local_id: u32, remote_id: u32) -> Self {
        Self::new(A_CLSE, local_id, remote_id, Vec::new())
    }

    pub fn wrte(local_id: u32, remote_id: u32, data: Vec<u8>) -> Self {
        Self::new(A_WRTE, local_id, remote_id, data)
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let header_bytes = self.header.to_bytes();
        writer.write_all(&header_bytes)?;
        if !self.payload.is_empty() {
            writer.write_all(&self.payload)?;
        }
        writer.flush()?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header_buf = [0u8; AdbHeader::SIZE];
        reader.read_exact(&mut header_buf)?;

        let header = AdbHeader::from_bytes(&header_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut payload = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            reader.read_exact(&mut payload)?;
        }

        Ok(Self { header, payload })
    }
}
