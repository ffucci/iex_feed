use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::{fs::File, io::{Cursor, SeekFrom, Seek}};
use bytes::Bytes;
use byteorder::ReadBytesExt;
use pcap_parser::data::{get_packetdata, PacketData};
use bytes::BytesMut;

use bincode;
use iex_feed::iexdata::*;
use std::str;

fn deserialize_data<'a, T>(curr: &'a [u8], start : usize, message_data : &IEXMessageData) -> T
where
    T: serde::de::Deserialize<'a>,
{
    let total_size = message_data.length as usize;
    println!("total_size : {0}", total_size);
    let bytes_message = hex::encode(&curr[start..(start + total_size)]);
    println!("bytes message : {0}", bytes_message);
    let message : T = bincode::deserialize(&curr[start..(start + total_size)]).unwrap();
    return message;
}

fn main()
{
    let path = "./test/20180127_IEXTP1_TOPS1.6.pcap";
    // let path = "/Users/coding/Downloads/data_feeds_20170912_20170912_IEXTP1_TOPS1.6.pcap";
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("got new block");
                num_blocks += 1;

                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        // starting a new section, clear known interfaces
                        println!("data");
                        if_linktypes = Vec::new();
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                        println!("linktype {:?}", if_linktypes);
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        println!("=====> block data");
                        let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);
                        if let Some(packet) = res.clone()
                        {
                            match packet
                            {
                                PacketData::L2(curr) => { 
                                    let x = hex::encode(curr); 
                                    println!("{:?}",x);
                                    let frame_header_length = 42;
                                    let iex_message_header_length = 40;
                                    let mut start = 0;
                                    start += frame_header_length;
                                    if curr.len() >= 22
                                    {
                                        println!("init byte = {:x}",&curr[start]);
                                        let header_bytes = &curr[start..(start + iex_message_header_length)];
                                        let h : IEXHeader = bincode::deserialize(header_bytes).unwrap();
                                        println!("header = {:?}", h);
                                        start += iex_message_header_length;
                                        let mut cnt = h.message_count;
                                        let mut total_byte_count = 0;
                                        while cnt > 0
                                        {
                                            let message_data : IEXMessageData = bincode::deserialize(&curr[start..(start + 4)]).unwrap();
                                            println!("message_data = {:?}", message_data);
                                            // Remove the message length from the count
                                            start += 2;
                                            match message_data.msg_type
                                            {
                                                IEXMessageType::QuoteUpdateMessage => 
                                                {
                                                    let quote = deserialize_data::<QuoteUpdateMessage>(&curr, start, &message_data);
                                                    println!("quote : {:?}", quote);
                                                },
                                                IEXMessageType::ShortSalePriceTestStatus => 
                                                {
                                                    let short_sale : ShortSalePriceTestStatus = deserialize_data::<ShortSalePriceTestStatus>(&curr, start, &message_data);
                                                    println!("short sale message = {:?}", short_sale);
                                                },
                                                IEXMessageType::TradingStatusMessage => 
                                                {
                                                    let trading_status : TradingStatusMessage = deserialize_data::<TradingStatusMessage>(&curr, start, &message_data);
                                                    println!("trading status message = {:?}", trading_status);
                                                },
                                                IEXMessageType::SecurityDirectoryMessage => 
                                                {
                                                    let security_dir : SecurityDirectoryMessage = deserialize_data::<SecurityDirectoryMessage>(&curr, start, &message_data);
                                                    println!("security dir = {:?}", security_dir);
                                                },
                                                _ => println!("nothing to do!"),
                                            }
                                            
                                            start += message_data.length as usize;
                                            cnt -= 1;
                                            total_byte_count += 2 + message_data.length as usize;
                                        }

                                        eprintln!("total count : {0}", total_byte_count);
                                        assert_eq!(total_byte_count, h.payload_length as usize);
                                    }
 
                                },
                                PacketData::L3(_, _) | PacketData::L4(_, _) | PacketData::Unsupported(_) => todo!(),
                            }
                        }
                    },
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        {
                            let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);
                            if let Some(packet) = res.clone()
                            {
                                match packet
                                {
                                    PacketData::L2(curr) => { 
                                        let x = BytesMut::from(curr); 
                                        println!("values : {:?}", x);
                                    },
                                    PacketData::L3(_, _) | PacketData::L4(_, _) | PacketData::Unsupported(_) => todo!(),
                                }
                            }
                        }
                    },
                    PcapBlockOwned::NG(_) => {
                        // can be statistics (ISB), name resolution (NRB), etc.
                        eprintln!("unsupported block");
                    },
                    PcapBlockOwned::Legacy(_)
                    | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }

    }
    println!("num_blocks: {}", num_blocks);
}

