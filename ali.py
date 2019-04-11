#!/usr/bin/env python
# coding=utf-8

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526.DescribeSecurityGroupAttributeRequest import DescribeSecurityGroupAttributeRequest
from aliyunsdkecs.request.v20140526.RevokeSecurityGroupRequest import RevokeSecurityGroupRequest
from aliyunsdkecs.request.v20140526.AuthorizeSecurityGroupRequest import AuthorizeSecurityGroupRequest
from aliyunsdkecs.request.v20140526.DescribeSecurityGroupsRequest import DescribeSecurityGroupsRequest
import json


class AliEngine:

    def __init__(self, acs_client, sg_id):
        self.__client = acs_client
        self.__sg_id=sg_id

    def describe_rules(self):
        request = DescribeSecurityGroupAttributeRequest()
        request.set_accept_format('json')
        request.set_SecurityGroupId(self.__sg_id)
        response = self.__client.do_action_with_exception(request)
        obj = json.loads(str(response, encoding='utf-8'))
        return obj

    def describe_sg(self):

        request = DescribeSecurityGroupsRequest()
        request.set_accept_format('json')

        request.set_SecurityGroupIds([self.__sg_id])
        request.set_Tags([
            {
                "Key": "sg_proto"
            }
        ])
        response = self.__client.do_action_with_exception(request)
        obj = json.loads(str(response, encoding='utf-8'))
        return obj

    def remove_rule(self, rule_set):
        '''
        remove rule from security group 

        Args:
            sg_id - security group id
            rule_set - dictionary like this {'protocol': 'TCP', 'min': '1', 'max': '1', 'ip': '8.8.9.9/32'}
        '''
        request = RevokeSecurityGroupRequest()
        request.set_SecurityGroupId(self.__sg_id)
        # request.set_SourceCidrIp("8.8.9.9/32")
        request.set_SourceCidrIp(rule_set['ip'])
        # request.set_IpProtocol("TCP")
        request.set_IpProtocol(rule_set['protocol'].upper())
        # request.set_PortRange("1/65535")
        request.set_PortRange(str(rule_set['min'])+'/'+str(rule_set['max']))
        response = self.__client.do_action_with_exception(request)
        obj = json.loads(str(response, encoding='utf-8'))
        return obj

    def add_rule(self, rule_set):
        '''
        add rule to security group

        Args:
            sg_id - security group id
            rule_set - dictionary like this {'protocol': 'TCP', 'min': '1', 'max': '1', 'ip': '8.8.9.9/32'}
        '''
        request = AuthorizeSecurityGroupRequest()
        request.set_SecurityGroupId(self.__sg_id)
        # request.set_SourceCidrIp("8.8.9.9/32")
        request.set_SourceCidrIp(rule_set['ip'])
        # request.set_IpProtocol("TCP")
        request.set_IpProtocol(rule_set['protocol'].upper())
        # request.set_PortRange("1/65535")
        request.set_PortRange(str(rule_set['min'])+'/'+str(rule_set['max']))
        response = self.__client.do_action_with_exception(request)
        obj = json.loads(str(response, encoding='utf-8'))
        return obj

 
