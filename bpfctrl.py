import argparse
import subprocess


def argument_parse():
    parser = argparse.ArgumentParser(
        usage='%(prog)s [OPTIONS] -m <path> ACTIONS', add_help=False)
    path = parser.add_argument_group()
    path.add_argument('-m', '--map', required=True,
                      nargs=1, help='path to the eBPF map')
    options = parser.add_argument_group(title='OPTIONS')
    options.add_argument('-h', '--help', action='help',
                         help='show this help message and exit')
    actions = parser.add_argument_group(
        title='ACTIONS', description='At least one action is needed. Adding are done before removing.')
    actions.add_argument('-a', '--add', metavar=('ip1', 'ip2'), nargs='*',
                         default=[], help='add all the ip adresses given in the eBPF map')
    actions.add_argument('-r', '--remove', metavar=('ip1', 'ip2'), nargs='*',
                         default=[], help='remove all the ip adresses given in the eBPF map')
    actions.add_argument('-d', '--dump', action='store_true',
                         default=False, help='dump the eBPF map')
    args = parser.parse_args()

    if args.add == [] and args.remove == [] and args.dump == False:
        exit(parser.format_help())
    else:
        return args


args = argument_parse()
eBPF_map = args.map[0]
action = "update"
for ip in list(map(lambda item: item.split("."), args.add)):
    command = ["bpftool", "map", action, "pinned", eBPF_map, "key"]
    command.extend(ip)
    command.extend(["value", "0", "0", "0", "0"])
    subprocess.call(command)

action = "delete"
for ip in list(map(lambda item: item.split("."), args.remove)):
    command = ["bpftool", "map", action, "pinned", eBPF_map, "key"]
    command.extend(ip)
    subprocess.call(command)

if args.dump == True:
    subprocess.call(["bpftool", "map", "dump", "pinned", eBPF_map])
