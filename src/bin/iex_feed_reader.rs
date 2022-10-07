use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::data::{PacketData};
use bytes::BytesMut;
use iex_feed::packetprocessor::*;

use std::env;
use std::fs::File;

use clap::{command, Arg, ArgAction};

const FRAME_HEADER_LENGTH : usize = 42;

fn main()
{
    env::set_var("RUST_BACKTRA
    CE", "1");
    let matches = command!()// requires `cargo` feature
        .version("0.1.0")
        .author("Francesco Fucci")
        .about("Can read IEX pcap feeds")
        .arg(Arg::new("file")
                 .short('f')
                 .long("file")
                 .action(ArgAction::Append)
                 .help("PCAP file to be read")).get_matches();

    let default_path = &"./test/20180127_IEXTP1_TOPS1.6.pcap".to_string();
    let path = matches.get_one::<String>("file").unwrap_or(default_path);
    let result_file = File::open(path);
    if result_file.is_err()
    {
        println!("Cannot open the selected file: check the file path.");
        return;
    }
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, result_file.unwrap()).expect("PcapNGReader");
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
                        println!("=====> block data : epb.caplen {0}", epb.caplen);
                        let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);
                        packet_processor.process_packet_data(res, FRAME_HEADER_LENGTH);
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

