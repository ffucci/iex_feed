use chrono::{DateTime, Utc};
use chrono::serde::ts_nanoseconds;
use serde::{Serialize,Deserialize};

#[derive(Deserialize, Debug)]
pub struct IEXHeader
{
    pub version : u8,
    reserved : u8,
    pub protocol_id : u16,
    pub channel_id : u32,
    pub session_id : u32,
    pub payload_length: u16,
    pub message_count : u16,
    pub stream_offset : u64,
    pub first_message_seq_number : u64,
    #[serde(with = "ts_nanoseconds")]
    pub send_time : DateTime<Utc>, 
}

#[derive(Deserialize, Debug)]
pub struct IEXMessageData
{
    pub length : u16,
    pub msg_type : u8,
    pub msg_flags : u8,
}