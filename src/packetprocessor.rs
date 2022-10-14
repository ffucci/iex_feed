use std::any::Any;
use std::fmt::Debug;
use std::fmt::Display;

use crate::iexdata::*;
use pcap_parser::data::PacketData;

fn deserialize_data<'a, T>(curr: &'a [u8], start: usize, message_data: &IEXMessageData) -> T
where
    T: serde::de::Deserialize<'a>,
{
    let total_size = message_data.length as usize;
    println!("total_size : {0}", total_size);
    let bytes_message = hex::encode(&curr[start..(start + total_size)]);
    println!("bytes message : {0}", bytes_message);
    let message: T = bincode::deserialize(&curr[start..(start + total_size)]).unwrap();
    return message;
}

pub trait PacketProcessor {
    fn process_packet_data(
        &self,
        data: Option<PacketData>,
        frame_header_length: usize,
    ) -> IEXPacket;
}

pub struct IEXPacketProcessor {}

#[derive(Debug)]
pub struct IEXPacket {
    pub header: Option<IEXHeader>,
    pub payload: Vec<Box<dyn Any>>,
}

#[derive(Debug)]
struct Dummy {}

impl PacketProcessor for IEXPacketProcessor {
    // process packet data
    fn process_packet_data(
        &self,
        data: Option<PacketData>,
        frame_header_length: usize,
    ) -> IEXPacket {
        let packet = data.expect("Impossible to process packet");

        let r: IEXPacket = match packet {
            PacketData::L2(curr) => {
                let x = hex::encode(curr);
                println!("{:?}", x);
                let mut start = 0;
                start += frame_header_length;

                let iex_message_header_length = 40;
                let mut return_packet = IEXPacket {
                    header: None,
                    payload: vec![],
                };
                let header_bytes = &curr[start..(start + iex_message_header_length)];
                let header: IEXHeader = bincode::deserialize(header_bytes).unwrap();
                println!("header = {:?}", header);
                start += iex_message_header_length;
                let mut cnt = header.message_count;
                println!("cnt : {0}", cnt);
                let mut total_byte_count = 0;
                let payload_length = header.payload_length;
                return_packet.header = Some(header);
                println!("start : {0}", start);
                while cnt > 0 {
                    let message_data: IEXMessageData =
                        bincode::deserialize(&curr[start..(start + 4)]).unwrap();
                    println!("message_data = {:?}", message_data);

                    // Remove the message length from the count
                    start += 2;

                    let single_packet: Box<dyn Any> = match message_data.msg_type {
                        IEXMessageType::QuoteUpdateMessage => {
                            let quote =
                                deserialize_data::<QuoteUpdateMessage>(&curr, start, &message_data);
                            println!("quote : {:?}", quote);
                            Box::new(quote)
                        }
                        IEXMessageType::ShortSalePriceTestStatus => {
                            let short_sale: ShortSalePriceTestStatus =
                                deserialize_data::<ShortSalePriceTestStatus>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                            // println!("short sale message = {:?}", short_sale);
                            Box::new(short_sale)
                        }
                        IEXMessageType::TradeReportMessage => {
                            let trade_report_message: TradeReportMessage =
                                deserialize_data::<TradeReportMessage>(&curr, start, &message_data);
                            // println!("trading report message = {:?}", trade_report_message);
                            Box::new(trade_report_message)
                        }
                        IEXMessageType::TradingStatusMessage => {
                            let trading_status: TradingStatusMessage =
                                deserialize_data::<TradingStatusMessage>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                            // println!("trading status message = {:?}", trading_status);
                            Box::new(trading_status)
                        }
                        IEXMessageType::SecurityDirectoryMessage => {
                            let security_dir: SecurityDirectoryMessage =
                                deserialize_data::<SecurityDirectoryMessage>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                            // println!("security dir = {:?}", security_dir);
                            Box::new(security_dir)
                        }
                        IEXMessageType::RetailLiquidityIndicator => {
                            let retail_indicator: RetailLiquidityIndicator =
                                deserialize_data::<RetailLiquidityIndicator>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                            // println!("retail update  = {:?}", retail_indicator);
                            Box::new(retail_indicator)
                        }
                        IEXMessageType::AuctionInformationMessage => {
                            let auction_message: AuctionInformationMessage =
                                deserialize_data::<AuctionInformationMessage>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                            // println!("auction message  = {:?}", auction_message);
                            Box::new(auction_message)
                        }
                        _ => {
                            // println!("message not processed yet: nothing to do!");
                            Box::new(Dummy {})
                        }
                    };

                    println!("{:?}", single_packet);
                    return_packet.payload.push(single_packet);
                    start += message_data.length as usize;
                    cnt -= 1;
                    total_byte_count += 2 + message_data.length as usize;
                }

                // eprintln!("total count : {0}", total_byte_count);
                assert_eq!(total_byte_count, payload_length as usize);
                return_packet
            }
            PacketData::L3(_, _) | PacketData::L4(_, _) | PacketData::Unsupported(_) => todo!(),
        };

        return r;
    }
}

#[cfg(test)]
mod tests {
    use std::{any::Any, str::FromStr};

    use chrono::{DateTime, Utc};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    const header_length : usize = 40;

    #[test]
    fn test_can_read_trading_status() {
        let packet_processor: IEXPacketProcessor = IEXPacketProcessor {};
        let test_header = IEXHeader {
            version: 1,
            __reserved: 0,
            protocol_id: 32771,
            channel_id: 1,
            session_id: 1150681088,
            payload_length: 24,
            message_count: 1,
            stream_offset: 1140157,
            first_message_seq_number: 37965,
            send_time: Utc::now(),
        };
        let by = bincode::serialize(&test_header);
        assert_eq!(by.is_ok(), true);
        assert_eq!(by.as_ref().unwrap().len(), 40);

        let raw_packet: Vec<u8> = vec![
            0x16, 0x00, 0x48, 0x48, 0xac, 0x63, 0xc0, 0x20, 0x96, 0x86, 0x6d, 0x14, 0x5a, 0x49,
            0x45, 0x58, 0x54, 0x20, 0x20, 0x20, 0x54, 0x31, 0x20, 0x20,
        ];

        let res: Vec<u8> = [by.unwrap(), raw_packet].concat();
        assert_eq!(res.len(), test_header.payload_length as usize + header_length);
        let expected_packet = packet_processor.process_packet_data(Some(PacketData::L2(&res)), 0);
        let expected_message = TradingStatusMessage {
            trading_status: TradingStatus::Halt,
            timestamp: DateTime::<Utc>::from_str("2016-08-23T19:30:32.572715948Z").unwrap(),
            symbol: [0x5a, 0x49, 0x45, 0x58, 0x54, 0x20, 0x20, 0x20], // ZIEXT
            reason: [0x54, 0x31, 0x20, 0x20],
            __t: 0x48,
        };
        let computed_message = expected_packet.payload[0].downcast_ref::<TradingStatusMessage>();
        assert_eq!(&expected_message, computed_message.unwrap());
    }

    #[test]
    fn test_can_read_quote_update_message() {
        let packet_processor: IEXPacketProcessor = IEXPacketProcessor {};
        let test_header = IEXHeader {
            version: 1,
            __reserved: 0,
            protocol_id: 32771,
            channel_id: 1,
            session_id: 1150681088,
            payload_length: 42 + 2, // Size of message plus 2
            message_count: 1,
            stream_offset: 1140157,
            first_message_seq_number: 37965,
            send_time: Utc::now(),
        };

        let header_bytes = bincode::serialize(&test_header);
        assert_eq!(header_bytes.is_ok(), true);
        assert_eq!(header_bytes.as_ref().unwrap().len(), header_length);

        let raw_packet: Vec<u8> = vec![
            0x2A, 0x00, 0x51, 0x00, 0xac, 0x63, 0xc0, 0x20, 0x96, 0x86, 0x6d, 0x14, 0x5a, 0x49,
            0x45, 0x58, 0x54, 0x20, 0x20, 0x20, 0xE4, 0x25, 0x00, 0x00, 0x24, 0x1d, 0x0f, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xec, 0x1d, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x03,
            0x00, 0x00
        ];

        let res: Vec<u8> = [header_bytes.unwrap(), raw_packet].concat();
        assert_eq!(res.len(), test_header.payload_length as usize + header_length);
        let expected_packet = packet_processor.process_packet_data(Some(PacketData::L2(&res)), 0);
        let expected_message = QuoteUpdateMessage::from(0x00, DateTime::<Utc>::from_str("2016-08-23T19:30:32.572715948Z").unwrap(), [0x5a, 0x49, 0x45, 0x58, 0x54, 0x20, 0x20, 0x20], 9700, 99.05000000000001, 99.07000000000001, 1000);
        let computed_message = expected_packet.payload[0].downcast_ref::<QuoteUpdateMessage>();
        assert_eq!(&expected_message, computed_message.unwrap());
    }

    #[test]
    fn test_can_read_short_sale_price_test_status_message() {
        let packet_processor: IEXPacketProcessor = IEXPacketProcessor {};
        let test_header = IEXHeader {
            version: 1,
            __reserved: 0,
            protocol_id: 32771,
            channel_id: 1,
            session_id: 1150681088,
            payload_length: 19 + 2, // Size of message plus 2
            message_count: 1,
            stream_offset: 1140157,
            first_message_seq_number: 37965,
            send_time: Utc::now(),
        };

        let header_bytes = bincode::serialize(&test_header);
        assert_eq!(header_bytes.is_ok(), true);
        assert_eq!(header_bytes.as_ref().unwrap().len(), header_length);

        let raw_packet: Vec<u8> = vec![
            0x13, 0x00, 0x50, 0x01, 
            0xac, 0x63, 0xc0, 0x20, 0x96, 0x86, 0x6d, 0x14, 
            0x5a, 0x49, 0x45, 0x58, 0x54, 0x20, 0x20, 0x20, 
            0x41
        ];

        let res: Vec<u8> = [header_bytes.unwrap(), raw_packet].concat();
        assert_eq!(res.len(), test_header.payload_length as usize + header_length);
        let expected_packet = packet_processor.process_packet_data(Some(PacketData::L2(&res)), 0);
        let expected_message = ShortSalePriceTestStatus::from(0x1, DateTime::<Utc>::from_str("2016-08-23T19:30:32.572715948Z").unwrap(), [0x5a, 0x49, 0x45, 0x58, 0x54, 0x20, 0x20, 0x20], 0x41);
        let computed_message = expected_packet.payload[0].downcast_ref::<ShortSalePriceTestStatus>();
        assert_eq!(&expected_message, computed_message.unwrap());
    }


}
