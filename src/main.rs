use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::{fs::File, io::{Cursor, SeekFrom, Seek}, os::unix::process};
use bytes::Bytes;
use byteorder::ReadBytesExt;
use pcap_parser::data::{get_packetdata, PacketData};
use bytes::BytesMut;
use iex_feed::packetprocessor::*;
use bincode;
use std::str;

fn main()
{
    let path = "./test/20180127_IEXTP1_TOPS1.6.pcap";
    // let path = "/Users/coding/Downloads/data_feeds_20170912_20170912_IEXTP1_TOPS1.6.pcap";
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    let packet_processor = IEXPacketProcessor{};
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
                        packet_processor.process_packet_data(res);
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

fn process_packet(res: &Option<PacketData>) {

}

