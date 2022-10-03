// Included crates
use chrono::{DateTime, Utc};
use chrono::serde::ts_nanoseconds;
use serde::{Serialize,Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};
use std::fmt;
use std::str;

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
    pub msg_type : IEXMessageType,
    pub msg_flags : u8,
}

#[derive(Deserialize_repr,Debug, PartialEq)]
#[repr(u8)]
pub enum IEXMessageType
{
    AuctionInformationMessage = 0x41,
    TradeBreakMessage = 0x42,
    SecurityDirectoryMessage = 0x44,
    TradingStatusMessage = 0x48,
    RetailLiquidityIndicator = 0x49,
    OperationalHaltMessage = 0x4f,
    ShortSalePriceTestStatus = 0x50,
    QuoteUpdateMessage = 0x51,
    SystemEventMessage = 0x53,
    TradeReportMessage = 0x54,
    OfficialPriceMessage = 0x58,
    Nothing,
}

#[derive(Debug, Deserialize)]
pub struct TradeReportMessage<'a>
{
    pub sale_condition_flags : u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp : DateTime<Utc>,
    pub symbol : &'a str,
    pub size : u32,
    pub price : i32,
    pub trade_id : i32,
}

#[derive(Debug, Deserialize)]
pub struct QuoteUpdateMessage
{
    t : u8,
    pub flags : u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp : DateTime<Utc>,
    pub symbol : [u8; 8],
    pub bid_size : u32,
    pub bid_price : i64,
    pub ask_price : i64,
    pub ask_size : u32,
}

#[derive(Debug, Deserialize)]
pub struct ShortSalePriceTestStatus
{
    t : u8,
    pub price_status : u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp : DateTime<Utc>,
    pub symbol : [u8; 8],
    pub detail : u8,
}

#[derive(Deserialize)]
pub struct TradingStatusMessage
{
    __t : u8,
    pub trading_status : u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp : DateTime<Utc>,
    pub symbol : [u8; 8],
    pub reason : [u8; 4],
}

impl fmt::Debug for TradingStatusMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = String::from_utf8(self.symbol.to_vec()).unwrap();
        let reason = String::from_utf8(self.reason.to_vec()).unwrap_or("NONE".to_string());

        f.debug_struct("TradingStatusMessage")
         .field("trading_status", &self.trading_status)
         .field("timestamp", &self.timestamp)
         .field("symbol", &symbol.trim())
         .field("reason", &reason.trim())
         .finish()
    }
}

#[derive(Debug,Deserialize)]
pub struct SecurityDirectoryMessage
{
    __t : u8,
    pub flags : u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp : DateTime<Utc>,
    pub symbol : [u8; 8],
    pub round_lot_size : u32,
    pub adjusted_poc_price : i64,
    pub luld_tier : LULDTier,    
}

#[derive(Deserialize_repr,Debug, PartialEq)]
#[repr(u8)]
pub enum LULDTier
{
    NotApplicable = 0x0,
    Tier1NMS = 0x1,
    Tier2NMS = 0x2,
}