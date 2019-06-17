import argparse
import ipaddress
import subprocess


def convert_to_ip(ip):
    """
        Convert a string into an IP address.

        :param ip: the ip to convert, can be like X.X.X.X or X.X.X.X.X.X, or
                   an int (decimal notation) converted into a string

        :return: an ip address
    """
    try:
        ip = ipaddress.ip_address(int(ip))
    except:
        ip = ipaddress.ip_address(ip)
    return ip


def convert_to_ip_value(ipval):
    """
        Convert a string into an IP address and the value associated.

        :param ip: the ip to convert, can be like X.X.X.X or X.X.X.X.X.X, or
                   an int (decimal notation) converted into a string

        :return: an array like [ip, value]
    """
    res = ipval.split(':')
    if len(res) == 1:
        res.append('')
    res[0] = convert_to_ip(res[0])
    res[1] = convert_to_ip(res[1])
    return res


def parser_creation():
    """
        Create a parser for the command line of the programm.

        :return: a parser
    """
    # messages display in the help
    des = {'help': 'show this help message and exit',
           'map': 'path to the eBPF map',
           'add': 'add all the ip adresses given in the eBPF map at the \
                   associated values',
           'remove': 'remove all the ip adresses given in the eBPF map',
           'dump': 'dump the eBPF map',
           # action group help
           'actions': 'At least one action is needed. Adding are done before removing.'}

    parser = argparse.ArgumentParser(
        usage='%(prog)s [OPTIONS] -m <path> ACTIONS', add_help=False)

    path = parser.add_argument_group()
    path.add_argument('-m', '--map', required=True, nargs=1, help=des['map'])

    options = parser.add_argument_group(title='OPTIONS')
    options.add_argument('-h', '--help', action='help', help=des['help'])

    actions = parser.add_argument_group(
        title='ACTIONS', description=des['actions'])
    actions.add_argument('-a', '--add', metavar=('ip:value'), nargs='*',
                         type=convert_to_ip_value, default=[], help=des['add'])
    actions.add_argument('-r', '--remove', metavar=('ip1', 'ip2'), nargs='*',
                         type=convert2ip, default=[], help=des['remove'])
    actions.add_argument('-d', '--dump', action='store_true',
                         default=False, help=des['dump'])

    return parser


def arg_parse():
    """
        Parse the command line

        :return: arguments as Namespace [option:[args]/Boolean]
    """
    parser = parser_creation()
    args = parser.parse_args()

    if args.add == [] and args.remove == [] and args.dump == False:
        exit(parser.format_help())
    else:
        return args


def map_modification(map, action, ips, values=[]):
    """
        Add or remove IP adresses of the eBPF map given.

        :param map: path to the eBPF map
        :param action: "update" or "delete"
        :param ips: a list of ip
        :param values: a list of the values associated with the ip of ips

        :return: None
    """
    for i in range(len(ips)):
        ip = str(ips[i]).split(".")
        val = str(values[i]).split(".")
        command = ["bpftool", "map", action, "pinned", map, "key"]
        command.extend(ip)
        if action == "update":
            command.append("value")
            command.extend(val)
        subprocess.call(command)


def map_dump(map):
    """
        Dump the eBPF map given.

        :param map: path to the eBPF map

        :return: None
    """
    subprocess.call(["bpftool", "map", "dump", "pinned", map])


def main():
    args = arg_parse()
    eBPF_map = args.map[0]
    add_ips = list(map(lambda pos: pos[0], args.add))
    add_value = list(map(lambda pos: pos[1], args.add))
    map_modification(eBPF_map, "update", add_ips, add_value)
    map_modification(eBPF_map, "delete", args.remove)
    if args.dump == True:
        map_dump(eBPF_map)


if __name__ == '__main__':
    main()
