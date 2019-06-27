# bpfctrl

A bpftool wrapper to handle eBPF maps.

## Setup instruction

### Prerequisites

You need to install ```bpftool```.

```
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/
$ cd linux/tools/bpf/bpftool/
$ make && sudo make install
$ sudo make doc-install
```

### bpfctrl installation

If ```pip3``` (```pip``` for Python3) is not installed on the system :
```
$ sudo apt-get install python3-pip
```

Then, in the same directory as the ```setup.py``` file of  ```bpfctrl```:
```
$ pip3 install .
```

## Examples of bpfctrl use
It can handle eBPF maps where keys are IPV4 addresses, and also maps that contain just one integer and key is 0.
The type of map has to be precised in the command line with ```ip``` for the first and ```uniq``` for the second.
### Map Modification
#### Ip
The following command line adds the IPV4 address 1.2.3.4 with the value 1 in the pinned map `/sys/fs/bpf/suricata-wlp4s0-ipv4_drop`.
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --add 1.2.3.4=1
```
This address can also be removed.
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --remove 1.2.3.4
```
It is possible to add or to remove several addresses at the same time.

#### Uniq
The following command line sets the value of the integer contained in the pinned map `/sys/fs/bpf/map` at 1.
```
$ sudo bpfctrl -m /sys/fs/bpf/map ip --set 1
```
### Map Access
With the flag ```--json```, the output of the program and the file written are in JSON format.

#### Both
The dump of the map is done with the flag ```--dump```
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --dump
1.2.3.4    28
3.3.3.3    8

$ sudo bpfctrl -m /sys/fs/bpf/map uniq --dump
1
```
The result of the dump can be store in a file if its paths is precised. If the file already exists, its content will be overwritten.
```
$ sudo bpfctrl  -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --dump ~/map.txt
```

#### Ip
The value associated at one IP is available with ```--get IP``` action.
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --get 3.3.3.3
1.1.1.1    4
```
Some eBPF maps store for each IP address, a value per CPU. With the flag ```--cpu```, ```dump``` and ```get``` commands conserve it on the final output. Without it, the value display is the sum of the value of each CPU.
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --get 3.3.3.3 --cpu
3.3.3.3    2    2    2    2


$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --get 3.3.3.3
3.3.3.3    8
```

### Combined Commands
The commands can be combined.
#### Ip
First, the program adds the elements and then removes. The dump of the map and the get are done at the end.
```
$ sudo bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ip --add 1.2.3.4=1 5.6.7.8=9 --remove 1.2.3.4 --dump --json
{
    "5.6.7.8": 9
}

```
#### Uniq
```
$ sudo bpfctrl -m /sys/fs/bpf/map uniq --set 3  --dump
3
```
