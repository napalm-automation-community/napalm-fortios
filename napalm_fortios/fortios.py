# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
from __future__ import unicode_literals

import re
from pyFG.fortios import FortiOS, FortiConfig, logger
from pyFG.exceptions import FailedCommit, CommandExecutionException
from napalm.base.exceptions import ReplaceConfigException, MergeConfigException
from napalm.base.utils.string_parsers import colon_separated_string_to_dict,\
                                             convert_uptime_string_seconds
import napalm.base.helpers
from napalm.base.base import NetworkDriver


class FortiOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password

        if optional_args is not None:
            self.vdom = optional_args.get('fortios_vdom', None)
        else:
            self.vdom = None

        self.device = FortiOS(hostname, username=username, password=password,
                              timeout=timeout, vdom=self.vdom)
        self.config_replace = False

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def is_alive(self):
            """Returns a flag with the state of the SSH connection."""
            return {
                'is_alive': self.device.ssh.get_transport().is_active()
            }

    def _execute_command_with_vdom(self, command, vdom=None):
        # If the user doesn't specify a particular vdom we use the default vdom for the object.
        vdom = vdom or self.vdom

        if vdom == 'global' and self.vdom is not None:
            # If vdom is global we go to the global vdom, execute the commands
            # and then back to the root. There is a catch, if the device doesn't
            # have vdoms enabled we have to execute the command in the root
            command = 'conf global\n{command}\nend'.format(command=command)

            # We skip the lines telling us that we changed vdom
            return self.device.execute_command(command)[1:-2]
        elif vdom not in ['global', None]:
            # If we have a vdom we change to the vdom, execute
            # the commands and then exit back to the root
            command = 'conf vdom\nedit {vdom}\n{command}\nend'.format(vdom=vdom, command=command)

            # We skip the lines telling us that we changed vdom
            return self.device.execute_command(command)[3:-2]
        else:
            # If there is no vdom we just execute the command
            return self.device.execute_command(command)

    def _get_command_with_vdom(self, cmd, separator=':', auto=False, vdom=None):
        output = self._execute_command_with_vdom(cmd, vdom)

        if auto:
            if ':' in output[0]:
                separator = ':'
            elif '\t' in output[0]:
                separator = '\t'
            else:
                raise Exception('Unknown separator for block:\n{}'.format(output))

        return colon_separated_string_to_dict('\n'.join(output), separator)

    def _load_config(self, filename, config):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        self.device.load_config(in_candidate=True, config_text=configuration)

    def load_replace_candidate(self, filename=None, config=None):
        self.config_replace = True

        self.device.candidate_config = FortiConfig('candidate')
        self.device.running_config = FortiConfig('running')

        self._load_config(filename, config)

        self.device.load_config(empty_candidate=True)

    def load_merge_candidate(self, filename=None, config=None):
        self.config_replace = False

        self.device.candidate_config = FortiConfig('candidate')
        self.device.running_config = FortiConfig('running')

        self._load_config(filename, config)

        for block in self.device.candidate_config.get_block_names():
            try:
                self.device.load_config(path=block, empty_candidate=True)
            except CommandExecutionException as e:
                raise MergeConfigException(e.message)

    def compare_config(self):
        return self.device.compare_config()

    def commit_config(self):
        try:
            self._execute_command_with_vdom('execute backup config flash commit_with_napalm')
            self.device.commit()
            self.discard_config()
        except FailedCommit as e:
            if self.config_replace:
                raise ReplaceConfigException(e.message)
            else:
                raise MergeConfigException(e.message)

    def discard_config(self):
        self.device.candidate_config = FortiConfig('candidate')
        self.device.load_config(in_candidate=True)

    def rollback(self):
        output = self._execute_command_with_vdom('fnsysctl ls -l data2/config', vdom=None)
        rollback_file = output[-2].split()[-1]
        rollback_config = self._execute_command_with_vdom(
            'fnsysctl cat data2/config/{rollback_file}'.format(rollback_file))

        self.device.load_config(empty_candidate=True)
        self.load_replace_candidate(config=rollback_config)
        self.device.candidate_config['vpn certificate local']['Fortinet_CA_SSLProxy'].\
            del_param('private-key')
        self.device.candidate_config['vpn certificate local']['Fortinet_CA_SSLProxy'].\
            del_param('certificate')
        self.device.candidate_config['vpn certificate local']['Fortinet_SSLProxy'].\
            del_param('private-key')
        self.device.candidate_config['vpn certificate local']['Fortinet_SSLProxy'].\
            del_param('certificate')
        self.device.commit()

    def get_config(self, retrieve="all"):
        """get_config implementation for FortiOS."""
        get_startup = retrieve == "all" or retrieve == "startup"
        get_running = retrieve == "all" or retrieve == "running"
        get_candidate = retrieve == "all" or retrieve == "candidate"

        if retrieve == "all" or get_running:
            result = self._execute_command_with_vdom('show')
            text_result = '\n'.join(result)

            return {
                'startup': u"",
                'running': str(text_result),
                'candidate': u"",
            }

        elif get_startup or get_candidate:
            return {
                'startup': u"",
                'running': u"",
                'candidate': u"",
            }

    def get_facts(self):
        system_status = self._get_command_with_vdom('get system status', vdom='global')
        performance_status = self._get_command_with_vdom('get system performance status',
                                                         vdom='global')

        interfaces = self._execute_command_with_vdom('get system interface | grep ==',
                                                     vdom='global')
        interface_list = [x.split()[2] for x in interfaces if x.strip() is not '']

        domain = self._get_command_with_vdom('get system dns | grep domain',
                                             vdom='global')['domain']

        return {
            'vendor': str('Fortigate'),
            'os_version': str(system_status['Version'].split(',')[0].split()[1]),
            'uptime': convert_uptime_string_seconds(performance_status['Uptime']),
            'serial_number': str(system_status['Serial-Number']),
            'model': str(system_status['Version'].split(',')[0].split()[0]),
            'hostname': str(system_status['Hostname']),
            'fqdn': u'{}.{}'.format(system_status['Hostname'], domain),
            'interface_list': interface_list
        }

    @staticmethod
    def _get_tab_separated_interfaces(output):
        interface_statistics = {
            'is_up': ('up' in output['State'] and 'up' or 'down'),
            'speed': output['Speed'],
            'mac_adddress': output['Current_HWaddr']
        }
        return interface_statistics

    @staticmethod
    def _get_unsupported_interfaces():
        return {
            'is_up': None,
            'is_enabled': None,
            'description': None,
            'last_flapped': None,
            'mode': None,
            'speed': None,
            'mac_address': None
        }

    def get_interfaces(self):
        cmd_data = self._execute_command_with_vdom('diagnose hardware deviceinfo nic',
                                                   vdom='global')

        interface_list = [x.replace('\t', '') for x in cmd_data if x.startswith('\t')]
        interface_statistics = {}
        for interface in interface_list:
            if_data = self._execute_command_with_vdom(
                'diagnose hardware deviceinfo nic {}'.format(interface), vdom='global')
            parsed_data = {}
            if interface.startswith('mgmt'):
                for line in if_data:
                    if line.startswith('Speed'):
                        if line.split('\t')[-1].split(' ')[0].isdigit():
                            parsed_data['speed'] = int(line.split('\t')[-1].split(' ')[0])
                        else:
                            parsed_data['speed'] = -1
                    elif line.startswith('Link'):
                        parsed_data['is_up'] = line.split('\t')[-1] is 'up'
                    elif line.startswith('Current_HWaddr'):
                        parsed_data['mac_address'] = str(line.split('\t')[-1])
                parsed_data['is_enabled'] = True
                parsed_data['description'] = u''
                parsed_data['last_flapped'] = -1.0
            else:
                for line in if_data:
                    if line.startswith('Admin'):
                        parsed_data['is_enabled'] = line.split(':')[-1] is 'up'
                    elif line.startswith('PHY Status'):
                        parsed_data['is_up'] = line.split(':')[-1] is 'up'
                    elif line.startswith('PHY Speed'):
                        parsed_data['speed'] = int(line.split(':')[-1])
                    elif line.startswith('Current_HWaddr'):
                        parsed_data['mac_address'] = str(line.split(' ')[-1])
                parsed_data['description'] = u''
                parsed_data['last_flapped'] = -1.0
            interface_statistics[interface] = parsed_data
        return interface_statistics

    def get_interfaces_ip(self):
        cmd = self._execute_command_with_vdom('get system interface physical', vdom='global')
        interface_ip_dictionary = {}
        if_name = None
        for line in cmd:
            interface_data = line.strip().split()
            if len(interface_data)==0:
                continue
            if interface_data[0].startswith('==['):
                m = re.search("==\[(.+)\]", interface_data[0])
                if_name = m.group(1)
            if if_name and interface_data[0]=="ip:" and interface_data[1][0]!='0':
                interface_ip_dictionary[if_name]={}
                interface_ip_dictionary[if_name]["ipv4"]={interface_data[1]: {'prefix_length': sum(bin(int(x)).count('1') for x in interface_data[2].split('.'))}}
            if if_name and interface_data[0]=="ipv6:" and interface_data[1][0]!=':':
                try:
                    interface_ip_dictionary[if_name]["ipv6"]={interface_data[1].split('/')[0]: {'prefix_length': interface_data[1].split('/')[1]}}
                except:
                    interface_ip_dictionary[if_name]={"ipv6": {interface_data[1].split('/')[0]: {'prefix_length': interface_data[1].split('/')[1]}}}
        return interface_ip_dictionary

    @staticmethod
    def _search_line_in_lines(search, lines):
        for l in lines:
            if search in l:
                return l

    def get_firewall_policies(self):
        cmd = self._execute_command_with_vdom('show firewall policy')
        policy = dict()
        policy_id = None
        default_policy = dict()
        position = 1

        for line in cmd:
            policy_data = line.strip()
            if policy_data.find("edit") == 0:
                policy_id = policy_data.split()[1]
                policy[policy_id] = dict()
            if policy_id is not None:
                if len(policy_data.split()) > 2:
                    policy_setting = policy_data.split()[1]
                    policy[policy_id][policy_setting] = policy_data.split()[2].replace("\"", "")

        for key in policy:

            enabled = 'status' in policy[key]

            logtraffic = policy[key]['logtraffic'] if 'logtraffic' in policy[key] else False

            action = 'permit' if 'action' in policy[key] else 'reject'

            policy_item = dict()
            default_policy[key] = list()
            policy_item['position'] = position
            policy_item['packet_hits'] = -1
            policy_item['byte_hits'] = -1
            policy_item['id'] = str(key)
            policy_item['enabled'] = enabled
            policy_item['schedule'] = str(policy[key]['schedule'])
            policy_item['log'] = str(logtraffic)
            policy_item['l3_src'] = str(policy[key]['srcaddr'])
            policy_item['l3_dst'] = str(policy[key]['dstaddr'])
            policy_item['service'] = str(policy[key]['service'])
            policy_item['src_zone'] = str(policy[key]['srcintf'])
            policy_item['dst_zone'] = str(policy[key]['dstintf'])
            policy_item['action'] = str(action)
            default_policy[key].append(policy_item)

            position = position + 1
        return default_policy

    def get_bgp_neighbors(self):

        families = ['ipv4', 'ipv6']
        terms = dict({'accepted_prefixes': 'accepted', 'sent_prefixes': 'announced'})
        command_sum = 'get router info bgp sum'
        command_detail = 'get router info bgp neighbor {}'
        command_received = 'get router info bgp neighbors {} received-routes | grep prefixes '
        peers = dict()

        bgp_sum = self._execute_command_with_vdom(command_sum)

        re_neigh = re.compile("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
        neighbors = {n.split()[0]: n.split()[1:] for n in bgp_sum if re.match(re_neigh, n)}

        self.device.load_config('router bgp')

        for neighbor, parameters in neighbors.items():
            logger.debug('NEW PEER')
            neigh_conf = self.device.running_config['router bgp']['neighbor']['{}'.format(neighbor)]

            neighbor_dict = peers.get(neighbor, dict())

            if not neighbor_dict:
                neighbor_dict['local_as'] = int(bgp_sum[0].split()[7])
                neighbor_dict['remote_as'] = int(neigh_conf.get_param('remote-as'))
                neighbor_dict['is_up'] = 'never' != parameters[7] or False
                neighbor_dict['is_enabled'] = neigh_conf.get_param('shutdown') != 'enable' or False
                neighbor_dict['description'] = u''
                neighbor_dict['uptime'] = convert_uptime_string_seconds(parameters[7])
                neighbor_dict['address_family'] = dict()
                neighbor_dict['address_family']['ipv4'] = dict()
                neighbor_dict['address_family']['ipv6'] = dict()

            detail_output = [x.lower() for x in
                             self._execute_command_with_vdom(command_detail.format(neighbor))]
            m = re.search('remote router id (.+?)\n', '\n'.join(detail_output))
            if m:
                neighbor_dict['remote_id'] = str(m.group(1))
            else:
                raise Exception('cannot find remote router id for %s' % neighbor)

            for family in families:
                # find block
                x = detail_output.index(' for address family: {} unicast'.format(family))
                block = detail_output[x:]

                for term, fortiname in terms.items():
                    text = self._search_line_in_lines('%s prefixes' % fortiname, block)
                    t = [int(s) for s in text.split() if s.isdigit()][0]
                    neighbor_dict['address_family'][family][term] = t

                received = self._execute_command_with_vdom(
                    command_received.format(neighbor))[0].split()
                if len(received) > 0:
                    neighbor_dict['address_family'][family]['received_prefixes'] = received[-1]
                else:
                    # Soft-reconfig is not enabled
                    neighbor_dict['address_family'][family]['received_prefixes'] = 0
            peers[neighbor] = neighbor_dict

        return {
            'global': {
                'router_id': str(bgp_sum[0].split()[3]),
                'peers': peers
            }
        }

    def get_interfaces_counters(self):
        cmd = self._execute_command_with_vdom('fnsysctl ifconfig', vdom=None)
        if_name = None
        interface_counters = dict()
        for line in cmd:
            data = line.split('\t')
            if (data[0] == '' or data[0] == ' ') and len(data) == 1:
                continue
            elif data[0] != '':
                if_name = data[0]
                interface_counters[if_name] = dict()
            elif (data[1].startswith('RX packets') or data[1].startswith('TX packets')) and if_name:
                if_data = data[1].split(' ')
                direction = if_data[0].lower()
                interface_counters[if_name][direction + '_unicast_packets'] = \
                    int(if_data[1].split(':')[1])
                interface_counters[if_name][direction + '_errors'] = int(if_data[2].split(':')[1])
                interface_counters[if_name][direction + '_discards'] = int(if_data[2].split(':')[1])
                interface_counters[if_name][direction + '_multicast_packets'] = -1
                interface_counters[if_name][direction + '_broadcast_packets'] = -1
            elif data[1].startswith('RX bytes'):
                if_data = data[1].split(' ')
                interface_counters[if_name]['rx_octets'] = int(if_data[1].split(':')[1])
                try:
                    interface_counters[if_name]['tx_octets'] = int(if_data[6].split(':')[1])
                except IndexError:
                    interface_counters[if_name]['tx_octets'] = int(if_data[7].split(':')[1])
        return interface_counters

    def get_environment(self):

        def get_cpu(cpu_lines):
            output = dict()
            for l in cpu_lines:
                m = re.search('(.+?) states: (.+?)% user (.+?)% system (.+?)% nice (.+?)% idle', l)
                cpuname = m.group(1)
                idle = m.group(5)
                output[cpuname] = {
                    '%usage': 100.0 - int(idle)
                }
            return output

        def get_memory(memory_line):
            total, used = int(memory_line[1]) >> 20, int(memory_line[2]) >> 20  # byte to MB
            return dict(available_ram=total, used_ram=used)

        out = dict()

        #execute sensor detail is not available
        sensors_block = self._execute_command_with_vdom('execute sensor list', vdom='global')

        temperatures=dict()
        fans=dict()
        powers = dict()

        for line in sensors_block:
            m = re.search("([0-9]+?) (.+\s[0-9]+?) (.+?) value=([0-9\.]+)", line)
            if m:
                if "TMP" in m.group(2).strip():
                    sensor_name, temp_value=m.group(3).strip(), m.group(4)
                    temp_value=float(temp_value)
                    temperatures[sensor_name] = dict(temperature=temp_value, is_alert=False, is_critical=False)
                elif "FAN" in m.group(2):
                    fans[m.group(2)+" - "+m.group(3).strip()] = dict(status=True)
            else:
                m = re.search("([0-9]+?)\s(.+?)\s+alarm=([0-9]+)\s+value=([0-9\.]+)\s+threshold_status=([0-9]+)", line)
                if m:
                    if "TMP" in m.group(2) or "Temp" in m.group(2):
                        sensor_name, temp_value=m.group(2).strip(), m.group(4)
                        temp_value=float(temp_value)
                        temperatures[sensor_name] = dict(temperature=temp_value, is_alert=int(m.group(5)), is_critical=int(m.group(3)))
                    elif "FAN" in  m.group(2).upper():
                        fans[m.group(2).strip()] = dict(status=(not bool(int(m.group(3)))))
                    elif m.group(2)[0]=="+":
                        powers[ m.group(2).strip()] = dict(status=(not bool(int(m.group(3)))), capacity=-1.0, output=-1.0)

        out['fans'] = fans
        out['temperature'] = temperatures
        out['power'] = powers

        # cpu
        out['cpu'] = get_cpu(
            [x for x in
             self._execute_command_with_vdom('get system performance status | grep CPU',
                                             vdom='global')[1:] if x])

        # memory
        memory_block = self._execute_command_with_vdom('diag hard sys mem | grep Mem', vdom='global')
        out['memory'] = dict(available_ram=-1, used_ram=-1)
        for line in memory_block:
            if line.strip().startswith("MemTotal:"):
                out['memory']["available_ram"]=(int(line.split()[1])>>10)
            if line.strip().startswith("MemFree:"):
                out['memory']["used_ram"]=(int(line.split()[1])>>10)
            if line.strip().startswith("Mem:"):
                out['memory']=get_memory(line.split())

        return out

    def get_arp_table(self):

        arp_table = []
        command = "get sys arp"
        output = self._execute_command_with_vdom(command)

        # Skip the first line which is a header
        output = output[1:]

        for line in output:
            if len(line) > 0:
                address, age, mac, interface = line.split()
                entry = {
                    "interface": interface,
                    "mac": napalm.base.helpers.mac(mac).rstrip(),
                    "ip": address,
                    "age": age.replace("-", "-1"),
                }
                arp_table.append(entry)
        return arp_table

