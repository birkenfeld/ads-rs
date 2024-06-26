use byteorder::{ReadBytesExt, LE};

use crate::client::AMS_HEADER_SIZE;

#[derive(Clone, Debug, Default)]
pub struct AdsResponse {
    pub ret_cmd: u16,
    pub state_flags: u16,
    pub data_len: u32,
    pub error_code: u32,
    pub invoke_id: u32,
    pub source: Vec<u8>,
    pub result: u32,
    pub data: Option<Vec<u8>>,
}

impl AdsResponse {
    /// Creates a Message from recieved bytes
    pub fn from_bytes(reply: &Vec<u8>) -> Self {
        let mut ptr = &reply[22..];
        //let mut message =
        AdsResponse {
            ret_cmd: ptr.read_u16::<LE>().expect("size"),
            state_flags: ptr.read_u16::<LE>().expect("size"),
            data_len: ptr.read_u32::<LE>().expect("size"),
            error_code: ptr.read_u32::<LE>().expect("size"),
            invoke_id: ptr.read_u32::<LE>().expect("size"),
            source: reply[14..22].to_vec(),
            result: if reply.len() >= AMS_HEADER_SIZE + 4 {
                ptr.read_u32::<LE>().expect("size")
            } else {
                0 // this must be because an error code is already set
            },
            data: Some(reply[AMS_HEADER_SIZE + 4..].to_vec()),
        }
    }
}
