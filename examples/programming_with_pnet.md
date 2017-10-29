# Programming with `pnet`

This document has been adapted from the `tcpdump`'s [Programming with pcap](http://www.tcpdump.org/pcap.htm) guide, thanks!

Lets begin by explaining who this guide is for. Basic programming knowledge will be assumed, `Rust` knowledge is not expected and we will explain the code to a beginner as best as possible. Basic networking knowledge is expected as this is a network library after all! All code examples have been tested on MacOS 10.13.X, CentOS 7.4.X with the default Kernels.

# Getting Started

The first thing to understand is the general layout of a `pnet`. The flow of code is as follows:

1. We begin by selecting which interface we want to sniff on. In Linux this may be something like eth0, in BSD it may be xl1, MacOS en0, etc. We can either ask the user for the wanted network interface, or we can ask `pnet` to provide us with the name of an interface that will do the job.
2. Initialize `pnet`. This is where we actually tell `pnet` what device we are sniffing on. We can, if we want to, sniff on multiple devices. How do we differentiate between them? Using file handles. Just like opening a file for reading or writing, we must name our sniffing "session" so we can tell it apart from other such sessions.
3. ~~In the event that we only want to sniff specific traffic (e.g.: only TCP/IP packets, only packets going to port 23, etc) we must create a rule set, "compile" it, and apply it. This is a three phase process, all of which is closely related. The rule set is kept in a `String`, and is converted into a format that `pnet` can read (hence compiling it). The compilation is actually just done by calling a function within our program; it does not involve the use of an external application. Then we tell `pnet` to apply it to whichever session we wish for it to filter.~~
4. Finally, we tell `pnet` to enter it's primary execution loop. In this state, `pnet` waits until it has received however many packets we want it to. Every time it gets a new packet in, it calls another function that we have already defined. The function that it calls can do anything we want; it can dissect the packet and print it to the user, it can save it in a file, or it can do nothing at all.
5. After our sniffing needs are satisfied, we close our session and are complete. 

This is actually a very simple process. Five steps total, one of which is optional (step 3, in case you were wondering). Let's take a look at each of the steps and how to implement them.

# Anaomity of a Basic `pnet` program

## Step 1: Getting/Setting the Device

This is very simple, but nowadays there are many devices on machines, so we need to make sure we're selecting the correct device or else we might not see any packets (or that packets we are expecting). There are a couple ways to find out the network interface:

- Linux
 - `/sbin/ip link show | grep 'state UP'`
  - This is the most up-to-date application for the network interfaces and highly reccomended
  - You can install this if you are missing it by `yum (or apt-get) install iproute`

- MacOS
 - `networksetup -listallhardwareports` 
    - This is the recommended way to get the network interfaces

- Using `pnet`
 - We can always use `pnet` to list out the interfaces (first example time!): 
 - first run `cargo new interfaces --bin` then make the adjustments in the files:

Cargo.toml: 

```
[dependencies]
pnet = "0.19.0" #~~still this version?~~
```

main.rs:

```rust
extern crate pnet;
use pnet::datalink::{self, NetworkInterface};

fn main() {
    let interfaces = datalink::interfaces();

    for en in interfaces.iter() {
        println!("{:?}", en);
    }
}
```

Then call: `./target/debug/interfaces` You should see something like: 

```
NetworkInterface { name: "lo0", index: 1, mac: Some(00:00:00:00:00:00), ips: [V4(Ipv4Network { addr: 127.0.0.1, prefix: 8 }), V6(Ipv6Network { addr: ::1, prefix: 128 }), V6(Ipv6Network { addr: fe80::1, prefix: 64 })], flags: 32841 }
NetworkInterface { name: "gif0", index: 2, mac: Some(00:00:00:00:00:00), ips: [], flags: 32784 }
NetworkInterface { name: "stf0", index: 3, mac: Some(00:00:00:00:00:00), ips: [], flags: 0 }
NetworkInterface { name: "XHC0", index: 4, mac: Some(00:00:00:00:00:00), ips: [], flags: 0 }
NetworkInterface { name: "XHC20", index: 5, mac: Some(00:00:00:00:00:00), ips: [], flags: 0 }
NetworkInterface { name: "XHC1", index: 6, mac: Some(00:00:00:00:00:00), ips: [], flags: 0 }
NetworkInterface { name: "en5", index: 7, mac: Some(aa:aa:aa:aa:aa:aa), ips: [V6(Ipv6Network { addr: fe80::0001, prefix: 64 })], flags: 34915 }
NetworkInterface { name: "en3", index: 8, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 35171 }
NetworkInterface { name: "en1", index: 9, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 35171 }
NetworkInterface { name: "en4", index: 10, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 35171 }
NetworkInterface { name: "en2", index: 11, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 35171 }
NetworkInterface { name: "en0", index: 12, mac: Some(aa:aa:aa:aa:aa:aa), ips: [V6(Ipv6Network { addr: fe80::0001, prefix: 64 }), V4(Ipv4Network { addr: 192.168.1.2, prefix: 8 })], flags: 34915 }
NetworkInterface { name: "p2p0", index: 13, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 34883 }
NetworkInterface { name: "awdl0", index: 14, mac: Some(aa:aa:aa:aa:aa:aa), ips: [V6(Ipv6Network { addr: fe80::0001, prefix: 64 })], flags: 35139 }
NetworkInterface { name: "bridge0", index: 15, mac: Some(aa:aa:aa:aa:aa:aa), ips: [], flags: 34915 }
NetworkInterface { name: "utun0", index: 16, mac: Some(aa:aa:aa:aa:aa:aa), ips: [V6(Ipv6Network { addr: fe80::0001, prefix: 64 })], flags: 32849 }
NetworkInterface { name: "utun1", index: 17, mac: Some(aa:aa:aa:aa:aa:aa), ips: [V6(Ipv6Network { addr: fe80::0001, prefix: 64 })], flags: 32849 }
``` 

This also gives us a great insite into the NetworkInterfaces data structure.

From here we can pick an interface to sniff. Let's subscript to the interface `en0` because it has an active IPv4 address.

## Opening The Device for Sniffing

Using the base code above let's open the interface for printing out the raw bytes of the first ten packets:

```rust
extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

use std::io;
use std::io::prelude::*; 

fn main() {
    //grabs all the interfaces on the machine
    let interfaces = datalink::interfaces();

    //grabbing the interface from the user
    let mut interface_name = String::new();
    print!("Which interface to sniff: ");
    io::stdout().flush().expect("Could not flush the stdout buffer, this is not good");
    io::stdin().read_line(&mut interface_name).expect("Error bad input");
    interface_name.trim();
    interface_name.pop();

    //Matching the name of the interface to the user defined name
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name; //creating an interface struture to match against

    let net_interface = interfaces.into_iter().filter(&interface_names_match).next()
        .expect(&format!("No interface found with the name: {}", &interface_name)); //grabbing the matching interface


    let (_tx, mut rx) = match datalink::channel(&net_interface, Default::default()) { //pulling out the layer 2 (datalink: Ethernet)
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => (panic!("Unhandled channel type")),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop { //create an infinte loop to iterate over the receiver and print out packet structure
        match rx.next() {
            Ok(packet) => println!("{:?}", packet), //prints out the decimal representaiton of the bytes received
            Err(x) => println!("Oh no! Something went wrong getting the next packet: {:?}", x)
        }
    }
}
```