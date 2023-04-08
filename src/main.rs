use pcap::Capture;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

fn process_ipv4_packet(i_packet: &Ipv4Packet) {
    match i_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let t_packet = TcpPacket::new(i_packet.payload());
            match t_packet {
                Some(tcp_packet) => {
                    println!(
                        "{:?}:{:?} -> {:?}:{:?}",
                        i_packet.get_source(),
                        tcp_packet.get_source(),
                        i_packet.get_destination(),
                        tcp_packet.get_destination()
                    );
                }
                None => {
                    println!("[!!] Sorry, unable to forge tcp packet");
                }
            }
        }
        IpNextHeaderProtocols::Udp => {
            // TODO: work on these protos as well
            //println!("[+] Udp packet detected !!");
        }
        _ => println!("[!!] Out of syllabus"),
    }
}

fn process_ether_packet(e_packet: &EthernetPacket) {
    match e_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip_packet = Ipv4Packet::new(e_packet.payload());
            match ip_packet {
                Some(i_packet) => {
                    process_ipv4_packet(&i_packet);
                }
                None => {
                    println!("[!!] Cannot forge IPv4 packet");
                }
            }
        }
        EtherTypes::Arp => {
            let arp_packet = ArpPacket::new(e_packet.payload());
            match arp_packet {
                Some(_a_packet) => {
                    // TODO: work on these protos as well
                    //println!("[+] Able to forge Arp packet");
                    //println!("{:?}", a_packet);
                }
                None => {
                    println!("[!!] Cannot forge ARP packet");
                }
            }
        }
        _ => println!("[!!] Out of syllabus"),
    }
}

fn main() {
    let mut cap = Capture::from_file("test.pcapng").unwrap();
    while let Ok(packet) = cap.next_packet() {
        let ether_packet = EthernetPacket::new(packet.data);
        match ether_packet {
            Some(e_packet) => {
                //println!("[+] Able to detect ethernet layer : {:?}", e_packet);
                // Process ethernet packet...
                process_ether_packet(&e_packet);
            }
            None => {
                println!("[!!] No ethernet layer present: {:?}", packet)
            }
        }
    }
}
