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

## Examples of bpfctrl use
The following command line adds the IPV4 address 1.2.3.4 with the value 1 in the pinned map `/sys/fs/bpf/suricata-wlp4s0-ipv4_drop`.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --add 1.2.3.4=1
```
This address can also be removed.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --remove 1.2.3.4
```
It is possible to add or to remove several addresses at the same time.


The dump of the map is done with the following command line.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --dump
{
    "1.2.3.4": 1
}
```
The result of the dump can be store in a file if its paths is precised. If the file already exists, its content will be overwritten.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --dump ~/map.txt
```

The commands can be combined. First, addings are done, then removing and the dump is done at the end.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --add 1.2.3.4=1 5.6.7.8=9 --remove 1.2.3.4 --dump
{
    "5.6.7.8": 9
}

```
