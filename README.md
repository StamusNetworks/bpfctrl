# bpfctrl

A bpftool wrapper to handle eBPF maps.

## Setup instruction
You need to install ```bpftool``.

```
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/
$ cd linux/tools/bpf/bpftool/
$ make && sudo make install
$ sudo make doc-install
```

## Examples of bpftool use
It is possible to add the IPV4 adress 1.2.3.4 with the value 1 on the pinned map `/sys/fs/bpf/suricata-wlp4s0-ipv4_drop` with the following command line.
```
$ sudo bpftool map update pinned /sys/fs/bpf/suricata-wlp4s0-ipv4_drop key 1 2 3 4 value 0 0 0 1
```
This address can also be removed.
```
$ sudo bpftool map delete pinned /sys/fs/bpf/suricata-wlp4s0-ipv4_drop key 1 2 3 4
```
The dump of the map is done with the following command line.
```
$ sudo bpftool map dump pinned /sys/fs/bpf/suricata-wlp4s0-ipv4_drop
key: 01 02 03 04  value: 00 00 00 01
Found 1 element
```
The result of the dump can be in a human readable JSON.

```
$ sudo bpftool map dump pinned /sys/fs/bpf/suricata-wlp4s0-ipv4_drop -p
[{
        "key": ["0x01","0x02","0x03","0x04"
        ],
        "value": ["0x00","0x00","0x00","0x01"
        ]
    }
]
```
