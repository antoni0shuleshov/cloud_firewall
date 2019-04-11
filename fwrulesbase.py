from abc import ABC, abstractmethod


class FwRulesBase(object):

    @abstractmethod
    def get_rules(self):
        raise NotImplementedError

    @abstractmethod
    def patch_rules(self, engine, ips: list):
        raise NotImplementedError

    @abstractmethod
    def build_rules(self, engine):
        raise NotImplementedError

    @abstractmethod
    def add_ips(self, ips):
        raise NotImplementedError

    def diff(self, new_rules):
        '''
        Compares arrays of old_ip and new_ip and creates new dectionary, which described which operations we should implement to create new_ip array
        Result {'add':[<ips to add>],'remove':[<ips to remove>],'none':[<ips not changed>]}
        '''
        old_rules_f = list(set([frozenset(x.items())
                                for x in self.get_rules()]))
        new_rules_f = list(set([frozenset(x.items()) for x in new_rules]))
        full_rules = set(old_rules_f+new_rules_f)
        return {'add': [dict(x) for x in list(full_rules-set(old_rules_f))],
                'remove': [dict(x) for x in list(full_rules-set(new_rules_f))],
                'none': [dict(x) for x in list(full_rules-set(list(full_rules-set(new_rules_f))+list(full_rules-set(old_rules_f))))]
                }
