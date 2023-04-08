use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::arp::ArpPacket;

fn process_ipv4_packet(i_packet: &Ipv4Packet) {
    println!("{:?} -> {:?}", i_packet.get_source(), i_packet.get_destination());
}


fn process_ether_packet(e_packet: &EthernetPacket) {
    match e_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip_packet = Ipv4Packet::new(e_packet.payload());
            match ip_packet {
                Some(i_packet) => {
                    process_ipv4_packet(&i_packet);
                },
                None => {
                    println!("[!!] Cannot forge IPv4 packet");
                }
            }
        },
        EtherTypes::Arp =>  {
            let arp_packet = ArpPacket::new(e_packet.payload());
            match arp_packet {
                Some(_a_packet) => {
                    //println!("[+] Able to forge Arp packet");
                    //println!("{:?}", a_packet);
                }, 
                None => {
                    println!("[!!] Cannot forge ARP packet");
                }
            }
        },
        _ => println!("[!!] Out of syllabus")
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
            },
            None => {
                println!("[!!] No ethernet layer present: {:?}", packet)
            }
        }
    }
}
