use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::{fs::File, io::{Cursor, SeekFrom, Seek}};
use bytes::Bytes;
use byteorder::ReadBytesExt;
use pcap_parser::data::{get_packetdata, PacketData};
use bytes::BytesMut;

use bincode;

use iex_feed::iexdata::*;

fn main()
{
    let path = "./src/20180127_IEXTP1_TOPS1.6.pcap";
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
                                    let mut c = Cursor::new(curr);
                                    println!("{:?}",x);
                                    if curr.len() >= 22
                                    {
                                        println!("init byte = {:x}",&curr[42]);
                                        c.seek(SeekFrom::Start(42));
                                        let header_bytes = &curr[42..82];
                                        let h : IEXHeader = bincode::deserialize(header_bytes).unwrap();
                                        println!("header = {:?}", h);
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
                eprintln!("Could not read complete data block.");
                eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                break;
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);
}

