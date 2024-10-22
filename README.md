# PicaPlay
My attempt  to play with PCAPs and underlying network layers in Rust


## Background
Previously I worked with pcap parsing and pcap rewriting in python3 using scapy library. (Which is a beast in itself)

Now I am trying to build same things and gain more understanding in Rust.



## Library being used
- `pnet`: I am using this library to learn the packet crafting from first principle point of view
- `pcap` : Reading the pcap and pcapng file format file


Focus will be on following tasks

- [x] Read packets from pcap/pcapng file
- [x] Decode tcp packet out of it
- [ ] Mutate Some of field of tcp packet
- [ ] Rewrite the modified packet back to pcap
- [ ] Send this packet to some Tcp process on remote host



  
