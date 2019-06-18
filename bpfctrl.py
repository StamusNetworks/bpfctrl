import argparse
import ipaddress
import json
import subprocess


def convert_to_ip(ip):
    """
        Convert a string into an IP address.

        :param ip: the ip to convert, can be like X.X.X.X or X:X:X:X:X:X, or
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

        TODO

        :return: an array like [ip, value]
    """
    res = ipval.split('=')
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
           'dump': 'dump the eBPF map, stored into a file if <path> is precised',
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
    actions.add_argument('-a', '--add', metavar=('IP=value'), nargs='+',
                         type=convert_to_ip_value, default=[], help=des['add'])
    actions.add_argument('-r', '--remove', metavar=('IP1', 'IP2'), nargs='+',
                         type=convert_to_ip, default=[], help=des['remove'])
    actions.add_argument('-d', '--dump', nargs='?', metavar=('<path>'),
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
        command = ["bpftool", "map", action, "pinned", map, "key"]
        command.extend(ip)
        if action == "update":
            val = str(values[i]).split(".")
            command.append("value")
            command.extend(val)
        subprocess.call(command)


def map_dump(map, path):
    """
        Dump the eBPF map given into a JSON file.

        :param map: path to the eBPF map
        :param path: path to the file in which the dump will be stored,
                     None if the dump is disply on stdout

        :return: None
    """
    call = subprocess.run(["bpftool", "map", "dump", "pinned",
                           map, "-j"], encoding='utf-8', stdout=subprocess.PIPE)
    res = json.loads(call.stdout)
    output = []
    for i in res:
        ip_hex = ''.join(['{0[2]}{0[3]}'.format(el, el) for el in i['key']])
        ip = str(ipaddress.ip_address(bytes.fromhex(ip_hex)))
        val_hex = ''.join(['{0[2]}{0[3]}'.format(el, el) for el in i['value']])
        val = int(val_hex, 16)
        output.append((ip, val))
    output = dict(output)
    if path == None:
        print(json.dumps(output, indent=4))
    else:
        with open(path, 'w') as file:
            json.dump(output, file, indent=4)


def main():
    args = arg_parse()
    eBPF_map = args.map[0]
    add_ips = list(map(lambda pos: pos[0], args.add))
    add_value = list(map(lambda pos: pos[1], args.add))
    map_modification(eBPF_map, "update", add_ips, add_value)
    map_modification(eBPF_map, "delete", args.remove)
    if args.dump != False:
        map_dump(eBPF_map, args.dump)


if __name__ == '__main__':
    main()
