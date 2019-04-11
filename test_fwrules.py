import unittest
from aliyunsdkcore.client import AcsClient

from .ali import AliEngine
from .alifwrules import AliFwRules


class Test_FwRules(unittest.TestCase):

    def assertArrayOfDict(self, source, target):
        def kf(arg):
            return hash(frozenset(arg.items()))
        self.assertListEqual(sorted(source, key=kf), sorted(target, key=kf))

    def setUp(self):
        self.gcp_tag_good = 'tcp:90-92-93,95,100-1000;udp;icmp'
        self.gcp_tag_bad = 'tcp:90-92-93,95,100-1000;udp;icmp;xxx'
        self.obj = AliFwRules()
        self.security_grp_id = 'sg-gw862fknew0norac0psa'
        self.eng = AliEngine(AcsClient('<ID>',
                                       '<Key>', 'eu-central-1'), self.security_grp_id)

    def test_main(self):
        AliFwRules().patch_rules(
            engine=self.eng, ips=['1.1.1.1','2.1.1.1','3.1.1.1'])
