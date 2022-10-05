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
    fn process_packet_data(&self, data: Option<PacketData>);
}

pub struct IEXPacketProcessor {}

impl PacketProcessor for IEXPacketProcessor {
    fn process_packet_data(&self, data: Option<PacketData>) {
        let frame_header_length = 42;
        let packet = data.expect("Impossible to process packet");

        match packet {
            PacketData::L2(curr) => {
                let x = hex::encode(curr);
                println!("{:?}", x);
                let iex_message_header_length = 40;
                let mut start = 0;
                start += frame_header_length;
                if curr.len() >= 22 {
                    let header_bytes = &curr[start..(start + iex_message_header_length)];
                    let h: IEXHeader = bincode::deserialize(header_bytes).unwrap();
                    println!("header = {:?}", h);
                    start += iex_message_header_length;
                    let mut cnt = h.message_count;
                    let mut total_byte_count = 0;
                    while cnt > 0 {
                        let message_data: IEXMessageData =
                            bincode::deserialize(&curr[start..(start + 4)]).unwrap();
                        println!("message_data = {:?}", message_data);
                        // Remove the message length from the count
                        start += 2;
                        match message_data.msg_type {
                            IEXMessageType::QuoteUpdateMessage => {
                                let quote = deserialize_data::<QuoteUpdateMessage>(
                                    &curr,
                                    start,
                                    &message_data,
                                );
                                println!("quote : {:?}", quote);
                            }
                            IEXMessageType::ShortSalePriceTestStatus => {
                                let short_sale: ShortSalePriceTestStatus =
                                    deserialize_data::<ShortSalePriceTestStatus>(
                                        &curr,
                                        start,
                                        &message_data,
                                    );
                                println!("short sale message = {:?}", short_sale);
                            }
                            IEXMessageType::TradeReportMessage => {
                                let trade_report_message: TradeReportMessage =
                                    deserialize_data::<TradeReportMessage>(
                                        &curr,
                                        start,
                                        &message_data,
                                    );
                                println!("trading report message = {:?}", trade_report_message);
                            }
                            IEXMessageType::TradingStatusMessage => {
                                let trading_status: TradingStatusMessage =
                                    deserialize_data::<TradingStatusMessage>(
                                        &curr,
                                        start,
                                        &message_data,
                                    );
                                println!("trading status message = {:?}", trading_status);
                            }
                            IEXMessageType::SecurityDirectoryMessage => {
                                let security_dir: SecurityDirectoryMessage =
                                    deserialize_data::<SecurityDirectoryMessage>(
                                        &curr,
                                        start,
                                        &message_data,
                                    );
                                println!("security dir = {:?}", security_dir);
                            }
                            IEXMessageType::RetailLiquidityIndicator => {
                                let retail_indicator: RetailLiquidityIndicator =
                                    deserialize_data::<RetailLiquidityIndicator>(
                                        &curr,
                                        start,
                                        &message_data,
                                    );
                                println!("retail update  = {:?}", retail_indicator);
                            }
                            _ => println!("nothing to do!"),
                        }

                        start += message_data.length as usize;
                        cnt -= 1;
                        total_byte_count += 2 + message_data.length as usize;
                    }

                    eprintln!("total count : {0}", total_byte_count);
                    assert_eq!(total_byte_count, h.payload_length as usize);
                }
            }
            PacketData::L3(_, _) | PacketData::L4(_, _) | PacketData::Unsupported(_) => todo!(),
        }
    }
}
