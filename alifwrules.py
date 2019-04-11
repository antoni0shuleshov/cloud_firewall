from .fwrulesbase import FwRulesBase
from .ali import AliEngine


class AliFwRules(FwRulesBase):
    def __init__(self):
        self.__rules = []
        self.__ips = {}

    def __add_rule(self, protocol, port_min=0, port_max=0):
        '''
        Adds firewall rule
        Args:
            protocol
            port_min
            port_max
        '''
        def __get_protocol_defaults(name):
            defaults = {
                'TCP': {'protocol': name, 'min': 1, 'max': 65535},
                'UDP': {'protocol': name, 'min': 1, 'max': 65535},
                'ICMP': {'protocol': name, 'min': -1, 'max': -1},
                'GRE': {'protocol': name, 'min': -1, 'max': -1},
                'ALL': {'protocol': name, 'min': -1, 'max': -1},
            }
            return defaults.get(name.upper())
        defaults = __get_protocol_defaults(protocol)
        if defaults == None:
            raise Exception('Unknown Protocol')
        if port_min >= defaults['min'] and port_min != 0:
            defaults['min'] = port_min
        if port_min <= defaults['max'] and port_max != 0:
            defaults['max'] = port_max
        self.__rules.append(
            {'protocol': protocol.upper(), 'min': defaults['min'], 'max': defaults['max']})
        return self

    def __build_from_gcp_tags(self, tags):
        '''
        Convert string representation of firewall rules in GCP format https://cloud.google.com/vpc/docs/firewalls#protocols_and_ports
        to array of rules dictionary {'protocol': '<>', 'min': '<>', 'max': '<>'}
        existing riles will be overwritten
            Args:  
                tags
        '''
        self.__rules = []
        sub_rules = tags.split(';')
        proto_definition = [
            [proto_definition for proto_definition in rec.split(':')] for rec in sub_rules]
        for p in proto_definition:
            if len(p) == 1:
                self.__add_rule(protocol=p[0])
            else:
                port_sets = p[1].split(',')
                for pr in port_sets:
                    prs = [int(i) for i in pr.split('-')]
                    if len(prs) == 1:
                        self.__add_rule(
                            protocol=p[0], port_min=prs[0], port_max=prs[0])
                    else:
                        self.__add_rule(
                            protocol=p[0], port_min=min(prs), port_max=max(prs))

    def __get_gcp_tags_from_aliresponse(self, engine):
        response = engine.describe_sg()
        r = [t1['TagValue'] for sg in response['SecurityGroups']['SecurityGroup']
             for t1 in sg['Tags']['Tag'] if t1['TagKey'] == 'sg_proto']
        if len(r) > 0:
            return r[0]

    def add_ips(self, ips):
        self.__ips = set(list(self.__ips) + list(ips))
        return self

    def get_rules(self):
        return [{**x, 'ip': y} for x in self.__rules for y in self.__ips]

    def build_rules(self, engine: AliEngine):
        '''
        build rules from Engine's response
        '''
        self.__build_from_gcp_tags(
            self.__get_gcp_tags_from_aliresponse(engine))
        return self

    def load_rules(self, engine: AliEngine):
        '''
        Builds rules from response in Alicloud format
        '''
        response = engine.describe_rules()
        self.__rules = [{'protocol': v['IpProtocol'].upper(), 'min':min([int(x) for x in v['PortRange'].split('/')]), 'max':max([int(x) for x in v['PortRange'].split('/')])}
                        if v['Policy'] == 'Accept' and v['Direction'] == 'ingress' else None for v in response["Permissions"]["Permission"]]
        self.__ips = {v['SourceCidrIp'] if v['Policy'] == 'Accept' and v['Direction']
                      == 'ingress' else None for v in response["Permissions"]["Permission"]}
        return self

    def patch_rules(self, engine: AliEngine, ips: list):
        '''
        apply `ips` array of IP addresses to security group `sg_id`

        Args:
            ips: array of IP addresses
            sg_id: id of security group
        '''
        operations = self.load_rules(engine).diff(
            AliFwRules().build_rules(engine).add_ips(ips).get_rules())
        print(operations)
        for o in operations['add']:
            engine.add_rule(o)
        for o in operations['remove']:
            engine.remove_rule(o)
