import argparse
import ipaddress
import json
import socket
import subprocess
import sys


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
    ip_int = int(ipaddress.ip_address(ip))
    ip = ipaddress.ip_address(socket.htonl(ip_int))
    return ip


def convert_to_value(val):
    """
        Transform a value (an string of uint 32) into an array of 4 str(int)
        corresponding of the value of each byte.
    """
    value = ipaddress.ip_address(int(val))
    value = str(value).split(".")
    return value


def convert_to_ip_value(ipval):
    """
        Convert a string into an IP address and the value associated.

        :param ipval: a string like 'ip=value'

        :return: an array like [ip, value]
    """
    res = ipval.split('=')
    if len(res) == 1:
        res.append('')
    res[0] = convert_to_ip(res[0])
    res[1] = convert_to_value(res[1])
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
           'dump': 'dump the eBPF map on stdout or in a file if <path> is \
                    precised',
           'get': 'Check if the IP is present on the map. If it is, displays\
                   its value.',
           'cpu': 'If dump or get options are activated, display the value for\
                   each cpu. If the eBPF map have not these precision, do\
                   nothing.',
           'json': 'The output will be in JSON format.',
           # action group help
           'actions': 'At least one action is needed. Adding are done before\
                       removing. Dump and get are executed after.'}

    parser = argparse.ArgumentParser(
        usage='%(prog)s [OPTIONS] -m <path> ACTIONS', add_help=False)

    path = parser.add_argument_group()
    path.add_argument('-m', '--map', required=True, nargs=1, help=des['map'])

    actions = parser.add_argument_group(
        title='ACTIONS', description=des['actions'])
    actions.add_argument('-a', '--add', metavar=('IP=value'), nargs='+',
                         type=convert_to_ip_value, default=[], help=des['add'])
    actions.add_argument('-r', '--remove', metavar=('IP1', 'IP2'), nargs='+',
                         type=convert_to_ip, default=[], help=des['remove'])
    actions.add_argument('-d', '--dump', nargs='?', metavar=('<path>'),
                         default=False, help=des['dump'])
    actions.add_argument('--get', nargs=1, metavar=('IP'),
                         type=convert_to_ip, default=False, help=des['get'])

    options = parser.add_argument_group(title='OPTIONS')
    options.add_argument('-h', '--help', action='help', help=des['help'])
    options.add_argument('--cpu', action='store_true',
                         default=False, help=des['cpu'])
    options.add_argument('--json', action='store_true',
                         default=False, help=des['json'])

    return parser


def arg_parse():
    """
        Parse the command line

        :return: arguments as Namespace [option:[args]/Boolean]
    """
    parser = parser_creation()
    args = parser.parse_args()

    if args.add == [] and args.remove == [] and args.dump == False and args.get == False:
        exit(parser.format_help())
    else:
        return args


def exit_bpf_error(stdout):
    """
        Exit with the error returned by bpf.

        :param stdout: output of the bpftool command like :
                       '{"error":"bpf obj get (/sys/fs/bpf): Permission
                        denied"}\n'
    """
    stdout = stdout.replace('"', "").replace("\n", "")
    stdout_split = stdout[1:len(stdout) - 1].split(":")
    sys.exit(stdout_split[2].lstrip())


def command_action(map, action, key):
    """Create a list of the commands to do action on the map with the key"""
    key = str(key).split(".")
    command = ["bpftool", "map", action, "pinned", map, "key"]
    command.extend(key)
    return command


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
        command = command_action(map, action, ips[i])
        if action == "update":
            command.append("value")
            command.extend(values[i])
        call = subprocess.run(command, encoding='utf-8',
                              stdout=subprocess.PIPE)
        if call.returncode != 0:
            exit_bpf_error(call.stdout)


def ip_ntohl(ip):
    """Return the ip address after application of the ntohl on it"""
    ip_int = int(ipaddress.ip_address(ip))
    ip_int = socket.ntohl(ip_int)
    return ipaddress.ip_address(ip_int)


def hex_array_to_ip(hex_array):
    """
        Transform an array of hexadecimal values "0xaa" into an IP address.

        :param array: an array of hexademial numbers "Oxaa"

        :return: an IP
    """
    ip_hex = ''.join(['{0[2]}{0[3]}'.format(el, el) for el in hex_array])
    return ip_ntohl(bytes.fromhex(ip_hex))


def hex_array_to_int(hex_array):
    """
        Transform an array of hexadecimal values "0xaa" into an int.

        :param array: an array of hexademial numbers "Oxaa"

        :return: an int
    """
    int_hex = ''.join(['{0[2]}{0[3]}'.format(el, el) for el in hex_array])
    return int(int_hex, 16)


def cpu_parse(json_result, dict_bool):
    """
        Parse a list of dictionnaries [{'cpu', 'value'} into a dictionnary or
        the sum of all the 'value'.

        :param json_result: a list of dictionnaries {'cpu', 'value'} where
                            'cpu' value is an int and 'value' value is an array
                            of hexadecimal number ["0xaa", ...]
        :param dict_bool: if True the result is a dictionnary, else an int.

        :return: a dictionnary {cpu:value, ...} or the sum of all the values.
    """
    vals = []
    for j in json_result:
        vals.append((j['cpu'], hex_array_to_int(j['value'])))
    vals = dict(vals)
    if dict_bool:
        return vals
    else:
        return sum(vals.values())


def parse_json_output(json_output, cpu_flag):
    """
        Parse a json output of a bpftool command, transform it in a dictionnary
        {ip:{cpu:int}} or {ip:int}. The value is computed by transforming the
        hexademimal values of the json output into an int.

        :param json_output: a dictionnary (obtained with a json.load command)
        :param cpu_flag: a boolean that indicates the type of dictionnary to
                         return

        :return: a dictionnary
    """
    output = []
    if not isinstance(json_output, list):
        json_output = [json_output]
    for j in json_output:
        key = str(hex_array_to_ip(j['key']))
        try:
            dump_value = j['values']
        except KeyError:
            dump_value = j['value']
            value = hex_array_to_int(dump_value)
        else:
            value = cpu_parse(dump_value, cpu_flag)
        output.append((key, value))
    return dict(output)


def output_string(dict, json_flag):
    """
        Given a dict {key:value} or {key:{cpu : val}}, create the output of the
        programm and return it as a string. It can be in JSON format if
        json_flag is True.
    """
    if json_flag:
        return json.dumps(dict, indent=4)

    keys = list(dict.keys())
    res = ""
    if isinstance(dict[keys[0]], int):
        for k in keys:
            res += "{}    {}\n".format(k, dict[k])
    else:
        for k in keys:
            values = list(dict[k].values())
            res += k + "    "
            res += "    ".join(['{}'.format(val) for val in values]) + "\n"
    return res[0:len(res) - 1]


def map_dump(map, path, cpu_flag, json_flag):
    """
        Print the dump of the eBPF map given or store it into a JSON file.

        :param map: path to the eBPF map
        :param path: path to the file in which the dump will be stored,
                     None if the dump is displayed on stdout.
        :param cpu_flag: A boolean that indicates if the value per cpu are
                         displayed (True) or if it is their sum. Do nothing if
                         the eBPF map have not the value per each cpu.
        :param json_flag: A boolean that indicates if the output is in JSON
                          format.

        :return: None
    """
    call = subprocess.run(["bpftool", "map", "dump", "pinned",
                           map, "-j"], encoding='utf-8', stdout=subprocess.PIPE)

    if call.returncode != 0:
        exit_bpf_error(call.stdout)

    dump = json.loads(call.stdout)
    dict = parse_json_output(dump, cpu_flag)
    output = output_string(dict, json_flag)
    if path == None:
        print(output)
    else:
        with open(path, 'w') as file:
            file.write(output)
            file.close()


def map_get(map, key, cpu_flag, json_flag):
    """
        Chek if an IP address is in the eBPF map given, if it is, display its
        value, else exit with an error.

        : param map: path to the eBPF map
        : param key: the ip to check(ipaddress)
        : param cpu_flag: A boolean that indicated if the value per cpu are
                         displayed(True) or if it is their sum. Do nothing if
                         the eBPF map have not a value per each cpu.
        :param json_flag: A boolean that indicates if the output is in JSON
                          format.

        : return: None
    """
    command = command_action(map, "lookup", key)
    command.append("-p")
    call = subprocess.run(command, encoding='utf-8', stdout=subprocess.PIPE)
    if call.returncode != 0:
        exit_bpf_error(call.stdout)

    res = call.stdout
    ip = str(ip_ntohl(key))
    if res == "null\n":
        sys.exit("The key {} is not in the map {}.".format(ip, map))

    output = parse_json_output(json.loads(res), cpu_flag)
    print(output_string(output, json_flag))


def main():
    args = arg_parse()
    eBPF_map = args.map[0]
    add_ips = list(map(lambda pos: pos[0], args.add))
    add_value = list(map(lambda pos: pos[1], args.add))
    map_modification(eBPF_map, "update", add_ips, add_value)
    map_modification(eBPF_map, "delete", args.remove)
    if args.dump != False:
        map_dump(eBPF_map, args.dump, args.cpu, args.json)
    if args.get != False:
        map_get(eBPF_map, args.get[0], args.cpu, args.json)


if __name__ == '__main__':
    main()
