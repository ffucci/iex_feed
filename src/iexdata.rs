use chrono::NaiveDateTime;
// Included crates
use chrono::serde::ts_nanoseconds;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt;
use std::str;
use time::serde::timestamp;

const K_MULT: f64 = 1e-4;

#[derive(Deserialize, Serialize, Debug)]
pub struct IEXHeader {
    pub version: u8,
    pub(crate) __reserved: u8,
    pub protocol_id: u16,
    pub channel_id: u32,
    pub session_id: u32,
    pub payload_length: u16,
    pub message_count: u16,
    pub stream_offset: u64,
    pub first_message_seq_number: u64,
    #[serde(with = "ts_nanoseconds")]
    pub send_time: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub struct IEXMessageData {
    pub length: u16,
    pub msg_type: IEXMessageType,
    pub msg_flags: u8,
}

#[derive(Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum IEXMessageType {
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

// AUCTION MESSAGES
#[derive(Deserialize_repr, Serialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum AuctionType {
    OPENING = 0x4F,
    CLOSING = 0x43,
    IPO = 0x49,
    HALT = 0x48,
    VOLATILITY = 0x56,
}

#[derive(Deserialize_repr, Serialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum ImbalanceSide {
    Buy = 0x42,
    Sell = 0x53,
    No = 0x4E,
    Unknown,
}

#[derive(Deserialize, Serialize)]
pub struct AuctionInformationMessage {
    __t: u8,
    pub auction_type: AuctionType,
    #[serde(with = "ts_nanoseconds")]
    pub send_time: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub paired_shares: u32,
    pub reference_price: i64,
    pub indicative_price: i64,
    pub imbalance_shares: u32,
    pub imbalance_side: ImbalanceSide,
    pub extension_number: u8,
    pub scheduled_auction_time: u32,
    pub auction_book_clearing_price: i64,
    pub collar_reference_price: i64,
    pub lower_auction_collar: i64,
    pub upper_auction_collar: i64,
}

impl fmt::Debug for AuctionInformationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = String::from_utf8(self.symbol.to_vec()).unwrap_or("NONE".to_string());
        // Create a NaiveDateTime from the timestamp
        let naive = NaiveDateTime::from_timestamp(self.scheduled_auction_time as i64, 0);
        // Create a normal DateTime from the NaiveDateTime
        let naive_datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);

        f.debug_struct("AuctionInformationMessage")
            .field("send time", &self.send_time)
            .field("symbol", &symbol.trim())
            .field("paired shares", &self.paired_shares)
            .field("reference price", &((self.reference_price as f64) * K_MULT))
            .field(
                "indicative price",
                &((self.indicative_price as f64) * K_MULT),
            )
            .field("imbalance shares", &self.imbalance_shares)
            .field("imbalance side", &self.imbalance_side)
            .field("extension_number", &self.extension_number)
            .field("scheduled auction time", &naive_datetime)
            .field(
                "auction book clearing price",
                &((self.auction_book_clearing_price as f64) * K_MULT),
            )
            .field(
                "collar reference price",
                &((self.collar_reference_price as f64) * K_MULT),
            )
            .field(
                "lower auction collar",
                &((self.lower_auction_collar as f64) * K_MULT),
            )
            .field(
                "upper auction collar",
                &((self.upper_auction_collar as f64) * K_MULT),
            )
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Deserialize)]
pub struct TradeReportMessage {
    __type: u8,
    pub sale_condition_flags: u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub size: u32,
    pub price: i64,
    pub trade_id: u64,
}

impl fmt::Debug for TradeReportMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = String::from_utf8(self.symbol.to_vec()).unwrap_or("NONE".to_string());

        f.debug_struct("TradeReportMessage")
            .field("sale condition flags", &self.sale_condition_flags)
            .field("timestamp", &self.timestamp)
            .field("symbol", &symbol.trim())
            .field("size", &self.size)
            .field("price", &((self.price as f64) * K_MULT))
            .field("trade id", &self.trade_id)
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Quote message update
#[derive(Deserialize, Serialize, PartialEq)]
pub struct QuoteUpdateMessage {
    t: u8,
    pub flags: u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub bid_size: u32,
    pub bid_price: i64,
    pub ask_price: i64,
    pub ask_size: u32,
}

impl QuoteUpdateMessage {
    pub fn from(
        flags : u8,
        timestamp: DateTime<Utc>,
        symbol: [u8; 8],
        bid_size: u32,
        bid_price: f32,
        ask_price: f32,
        ask_size: u32,
    ) -> QuoteUpdateMessage {
        QuoteUpdateMessage {
            t: IEXMessageType::QuoteUpdateMessage as u8,
            flags: flags,
            timestamp: timestamp,
            symbol: symbol,
            bid_size: bid_size,
            bid_price: (bid_price * 10000 as f32) as i64,
            ask_price: (ask_price * 10000 as f32) as i64,
            ask_size: ask_size,
        }
    }
}

impl fmt::Debug for QuoteUpdateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = String::from_utf8(self.symbol.to_vec()).unwrap_or("NONE".to_string());

        f.debug_struct("QuoteUpdateMessage")
            .field("flags", &self.flags)
            .field("timestamp", &self.timestamp)
            .field("symbol", &symbol.trim())
            .field("bid_size", &self.bid_size)
            .field("bid price", &((self.bid_price as f64) * 1e-4))
            .field("ask price", &((self.ask_price as f64) * 1e-4))
            .field("ask_size", &self.ask_size)
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Deserialize)]
pub struct ShortSalePriceTestStatus {
    t: u8,
    pub price_status: u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub detail: u8,
}

///////////// Trading Status ///////////////
#[derive(Deserialize_repr, Serialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum TradingStatus {
    Halt = 0x48,
    Acceptance = 0x4f,
    Paused = 0x50,
    Trading = 0x54,
    Unknown,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct TradingStatusMessage {
    pub(crate) __t: u8,
    pub trading_status: TradingStatus,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub reason: [u8; 4],
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

#[derive(Debug, Deserialize)]
pub struct SecurityDirectoryMessage {
    __t: u8,
    pub flags: u8,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
    pub round_lot_size: u32,
    pub adjusted_poc_price: i64,
    pub luld_tier: LULDTier,
}

#[derive(Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum LULDTier {
    NotApplicable = 0x0,
    Tier1NMS = 0x1,
    Tier2NMS = 0x2,
}

// Retail Indicator Message
// TOPS broadcasts this message each time there is an update to IEX
// eligible liquidity interest during the trading day
#[derive(Deserialize, Serialize)]
pub struct RetailLiquidityIndicatorMessage {
    __t: u8,
    pub retail_liquidity_indicator: RetailLiquidityIndicator,
    #[serde(with = "ts_nanoseconds")]
    pub timestamp: DateTime<Utc>,
    pub symbol: [u8; 8],
}

impl fmt::Debug for RetailLiquidityIndicatorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = String::from_utf8(self.symbol.to_vec()).unwrap();

        f.debug_struct("RetailLiquidityIndicatorMessage")
            .field("indicator", &self.retail_liquidity_indicator)
            .field("timestamp", &self.timestamp)
            .field("symbol", &symbol.trim())
            .finish()
    }
}

#[derive(Deserialize_repr, Serialize_repr, Debug, PartialEq)]
#[repr(u8)]
pub enum RetailLiquidityIndicator {
    SPACE = 0x20,
    BuyInterest = 0x41,
    SellInterest = 0x42,
    BuySellInterest = 0x43,
    UNKNOWN,
}
