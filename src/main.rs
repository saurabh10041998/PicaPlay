use pcap::Capture;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp;
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::{Packet, MutablePacket};
use std::net::Ipv4Addr;


fn modify_tcp_fields(t_packet: &TcpPacket, ipv4_source: &Ipv4Addr, ipv4_destination: &Ipv4Addr) {
    println!("[+] original tcp packet: {:#?}", t_packet);
    println!("Tommorow I will start tinkering with this");
    let mut buf = vec![0; t_packet.packet().len()];
    let new_tcp_packet = MutableTcpPacket::new(&mut buf);
    if let Some(mut n_t_packet) = new_tcp_packet {
        n_t_packet.clone_from(t_packet);
        n_t_packet.set_source(8080);
        n_t_packet.set_destination(443);
        // Set the checksum
        let checksum = tcp::ipv4_checksum(&n_t_packet.to_immutable(), ipv4_source, ipv4_destination);
        n_t_packet.set_checksum(checksum);        
        println!("[+] New tcp packet: {:#?}", n_t_packet);



        // Prepare Ipv4 and Etherpacket   
        let mut ip_buff = vec![0; 20 + n_t_packet.packet().len()];
        println!("Reserving: {:?}", ip_buff.len());
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ip_buff).unwrap();
        ipv4_packet.set_source(ipv4_source.clone());
        ipv4_packet.set_destination(ipv4_destination.clone());
        let ip_checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(ip_checksum);
        ipv4_packet.set_total_length((20 + n_t_packet.packet().len()) as  u16);
        ipv4_packet.set_payload(n_t_packet.packet_mut());

        println!("[+] Crafted ipv4 packet {:#?}", ipv4_packet);
    }    
}

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
                    modify_tcp_fields(&tcp_packet, &i_packet.get_source(), &i_packet.get_destination());
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
    let mut cap = Capture::from_file("test2.pcapng").unwrap();
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
