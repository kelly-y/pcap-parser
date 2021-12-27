# pcap-parser

### Introduction
This is a program which can read saved pacp file and parse the information. <br>
The following information can be displayed:
1. The **Timestamp** of the packet.
2. The **MAC source and destination Address** of the packet.
3. The **Ether Type** of the packet.
4. The **IP soruce and destination Address** of **IPv4** packet.
5. The **source and destination Port number** of **IPv4 TCP and UDP** packet.

### Way to execute
`$ make`: Compile C file `parser.c`. <br>
`$ make exe`: Start the parser. The parser will read `test.pcap` file and parse it. <br>
`$ make clean`: Remove all files produced by `$ make` instruction. <br>
`$ ./parser [pcap file]`: Put a pcap file in same level directory, and execute the program not using `$ make exe` instruction.

### Required tool
**`libpcap/pcap.h`** is needed, which might not exist in your environment. <br> <br>
To link `pcap.h` for successful compilation, <br> 
here is a necessary installation instruction before entering `$ make`. <br>
```
$ sudo apt-get install libpcap-dev
```
