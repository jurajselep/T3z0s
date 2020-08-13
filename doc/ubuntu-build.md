Ubuntu 20.04 Build
==================

              # apt update
              # apt install build-essential git cmake clang libssl-dev libglib2.0-dev libgcrypt-dev libc-ares-dev libpcap-dev bison flex qt5-default qtmultimedia5-dev
              $ make prepare
              $ make build

              You can find `tshark` and `wireshark` in `wireshakr/build` directory.

Verify that plugin is installed
-------------------------------

               $ run/tshark -G plugins | grep -i tezos
               tezos.so 0.0.1 dissector /usr/local/lib/wireshark/plugins/3.3/epan/tezos.so
               $ run/tshark -G protocols | grep -i tezos
               Tezos Protocol  tezos   tezos

Simple Session
--------------

- Terminal 1:

               $ run/tshark -r /tmp/xyz.pcap
                   1 0.000000000    127.0.0.1 ? 127.0.0.1    tezos 58
                   ...
                   3 1.147193109    127.0.0.1 ? 127.0.0.1    tezos 58
                   ...
                   5 1.842787799    127.0.0.1 ? 127.0.0.1    tezos 58

                $ run/tshark -Vr /tmp/xyz.pcap
                   ...
                Internet Control Message Protocol
                    Type: 3 (Destination unreachable)
                    Code: 3 (Port unreachable)
                    Checksum: 0x4951 [correct]
                    [Checksum Status: Good]
                    Unused: 00000000
                    Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
                        0100 .... = Version: 4
                        .... 0101 = Header Length: 20 bytes (5)
                        Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
                            0000 00.. = Differentiated Services Codepoint: Default (0)
                            .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
                        Total Length: 44
                        Identification: 0xd646 (54854)
                        Flags: 0x40, Don't fragment
                            0... .... = Reserved bit: Not set
                            .1.. .... = Don't fragment: Set
                            ..0. .... = More fragments: Not set
                        Fragment offset: 0
                        Time to live: 64
                        Protocol: UDP (17)
                        Header checksum: 0x6678 [validation disabled]
                        [Header checksum status: Unverified]
                        Source: 127.0.0.1
                        Destination: 127.0.0.1
                    User Datagram Protocol, Src Port: 44054, Dst Port: 1024
                        Source Port: 44054
                        Destination Port: 1024
                        Length: 24
                        Checksum: 0xfe2b [unverified]
                        [Checksum Status: Unverified]
                        [Stream index: 2]
                        UDP payload (16 bytes)
                Tezos Protocol
                        Tezos conversation: 0x7f0b31574890
                        [truncated]Tezos Msg: counter:1; addr_local:172.18.0.2:60064; addr_remote:51.15.220.7:9732; conn_msg_local:Some(ConnectionMessage { port: 19732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed

Currently, `tshark` generates debug log to `/tmp/xyz.log`, it is used only for development and contains eg. informations about analysed packets:

                $ cat /tmp/xyz.log
                ...
                R: Conversation: counter:1; addr_local:172.18.0.2:60064; addr_remote:51.15.220.7:9732; conn_msg_local:Some(ConnectionMessage { port: 19732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [216, 36, 109, 19, 208, 39, 12, 191, 255, 64, 70, 182, 217, 75, 5, 171, 25, 146, 11, 197, 173, 159, 183, 127, 62, 148, 92, 64, 179, 64, 232, 116], proof_of_work_stamp: [209, 208, 235, 213, 87, 132, 188, 146, 133, 45, 145, 61, 191, 15, 181, 21, 45, 80, 91, 86, 125, 147, 15, 178], message_nonce: [191, 34, 238, 188, 53, 68, 234, 4, 185, 179, 251, 148, 54, 131, 246, 130, 16, 14, 142, 130, 233, 96, 6, 50], body: BinaryDataCache { has_value: true, len: 134 } }); conn_msg_remote:None
                R: Conversation: counter:1; addr_local:172.18.0.2:35030; addr_remote:67.207.68.241:9732; conn_msg_local:Some(ConnectionMessage { port: 19732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [216, 36, 109, 19, 208, 39, 12, 191, 255, 64, 70, 182, 217, 75, 5, 171, 25, 146, 11, 197, 173, 159, 183, 127, 62, 148, 92, 64, 179, 64, 232, 116], proof_of_work_stamp: [209, 208, 235, 213, 87, 132, 188, 146, 133, 45, 145, 61, 191, 15, 181, 21, 45, 80, 91, 86, 125, 147, 15, 178], message_nonce: [59, 45, 26, 38, 237, 200, 110, 51, 149, 169, 58, 111, 173, 146, 13, 137, 77, 205, 136, 172, 239, 181, 244, 159], body: BinaryDataCache { has_value: true, len: 134 } }); conn_msg_remote:None
                R: Conversation: counter:2; addr_local:172.18.0.2:60064; addr_remote:51.15.220.7:9732; conn_msg_local:Some(ConnectionMessage { port: 19732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [216, 36, 109, 19, 208, 39, 12, 191, 255, 64, 70, 182, 217, 75, 5, 171, 25, 146, 11, 197, 173, 159, 183, 127, 62, 148, 92, 64, 179, 64, 232, 116], proof_of_work_stamp: [209, 208, 235, 213, 87, 132, 188, 146, 133, 45, 145, 61, 191, 15, 181, 21, 45, 80, 91, 86, 125, 147, 15, 178], message_nonce: [191, 34, 238, 188, 53, 68, 234, 4, 185, 179, 251, 148, 54, 131, 246, 130, 16, 14, 142, 130, 233, 96, 6, 50], body: BinaryDataCache { has_value: true, len: 134 } }); conn_msg_remote:Some(ConnectionMessage { port: 9732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [22, 138, 26, 190, 155, 136, 40, 188, 104, 21, 142, 120, 74, 112, 73, 226, 28, 188, 210, 36, 182, 108, 243, 143, 14, 181, 24, 46, 142, 252, 160, 93], proof_of_work_stamp: [167, 156, 211, 24, 253, 18, 59, 165, 169, 245, 0, 23, 37, 19, 76, 248, 81, 96, 25, 99, 250, 192, 179, 235], message_nonce: [133, 142, 139, 18, 93, 237, 171, 184, 126, 253, 81, 181, 210, 141, 185, 3, 146, 3, 115, 162, 236, 107, 90, 101], body: BinaryDataCache { has_value: true, len: 134 } })
                R: Conversation: counter:3; addr_local:172.18.0.2:60064; addr_remote:51.15.220.7:9732; conn_msg_local:Some(ConnectionMessage { port: 19732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [216, 36, 109, 19, 208, 39, 12, 191, 255, 64, 70, 182, 217, 75, 5, 171, 25, 146, 11, 197, 173, 159, 183, 127, 62, 148, 92, 64, 179, 64, 232, 116], proof_of_work_stamp: [209, 208, 235, 213, 87, 132, 188, 146, 133, 45, 145, 61, 191, 15, 181, 21, 45, 80, 91, 86, 125, 147, 15, 178], message_nonce: [191, 34, 238, 188, 53, 68, 234, 4, 185, 179, 251, 148, 54, 131, 246, 130, 16, 14, 142, 130, 233, 96, 6, 50], body: BinaryDataCache { has_value: true, len: 134 } }); conn_msg_remote:Some(ConnectionMessage { port: 9732, versions: [Version { chain_name: "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z", distributed_db_version: 0, p2p_version: 1 }], public_key: [22, 138, 26, 190, 155, 136, 40, 188, 104, 21, 142, 120, 74, 112, 73, 226, 28, 188, 210, 36, 182, 108, 243, 143, 14, 181, 24, 46, 142, 252, 160, 93], proof_of_work_stamp: [167, 156, 211, 24, 253, 18, 59, 165, 169, 245, 0, 23, 37, 19, 76, 248, 81, 96, 25, 99, 250, 192, 179, 235], message_nonce: [133, 142, 139, 18, 93, 237, 171, 184, 126, 253, 81, 181, 210, 141, 185, 3, 146, 3, 115, 162, 236, 107, 90, 101], body: BinaryDataCache { has_value: true, len: 134 } })
                ...
