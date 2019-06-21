# bpfctrl

A bpftool wrapper to handle eBPF maps.

## Setup instruction
You need to install ```bpftool```.

```
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/
$ cd linux/tools/bpf/bpftool/
$ make && sudo make install
$ sudo make doc-install
```

## Examples of bpfctrl use

### Map Modification
The following command line adds the IPV4 address 1.2.3.4 with the value 1 in the pinned map `/sys/fs/bpf/suricata-wlp4s0-ipv4_drop`.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --add 1.2.3.4=1
```
This address can also be removed.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --remove 1.2.3.4
```
It is possible to add or to remove several addresses at the same time.

### Map Access

The dump of the map is done with the following command line.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --dump
1.2.3.4    28
3.3.3.3    8

```
The result of the dump can be store in a file if its paths is precised. If the file already exists, its content will be overwritten.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --dump ~/map.txt
```
The value associated at one IP is available with ```--get IP``` action.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --get 3.3.3.3
1.1.1.1    4
```
Some eBPF maps store for each IP address, a value per CPU. With the flag ```--cpu```, ```dump``` and ```get``` commands conserve it on the final output. Without it, the value display is the sum of the value of each CPU.
```
$ sudo python3 ~/bpfctrl-2/bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --get 3.3.3.3 --cpu
3.3.3.3    2    2    2    2


$ sudo python3 ~/bpfctrl-2/bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --get 3.3.3.3
3.3.3.3    8
```

With the flag ```--json```, the output of the program and the file written are in JSON format.
### Combined Commands
The commands can be combined. First, the program adds the elements and then removes. The dump of the map and the get are done at the end.
```
$ sudo python3 bpfctrl.py -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop --add 1.2.3.4=1 5.6.7.8=9 --remove 1.2.3.4 --dump --json
{
    "5.6.7.8": 9
}

```
