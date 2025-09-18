from pandas._libs import properties
from pyexpat.errors import XML_ERROR_XML_DECL

from simulation.model import Identifiers, NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from simulation import model as m
from typing import Union
import numpy as np
import random
from py2neo import Graph, NodeMatcher, RelationshipMatcher
from typing import Dict

nodes = {}
credential_node = []
credential_port = []

def default_identifiers():
    graph = Graph('http://localhost:7474', auth=("neo4j", "qweasd"))
    node_matcher = NodeMatcher(graph)
    relationship_matcher = RelationshipMatcher(graph)
    data1 = node_matcher.match('Service').all()
    data2 = node_matcher.match('OS').all()
    properties = []
    for data in data1:
        properties.append(data['name'])
    ports = properties
    for data in data2:
        properties.append(data['name'])
    data3 = node_matcher.match('Vul').all()
    local_vul = []
    remote_vul = []
    for node in data3:
        relationship1 = list(relationship_matcher.match((node, None), r_type="type"))
        if relationship1[0].end_node['name'] == 'LOCAL':
            local_vul.append(str(relationship1[0].start_node['CVE_ID']))
        elif relationship1[0].end_node['name'] == 'REMOTE':
            remote_vul.append(str(relationship1[0].start_node['CVE_ID']))
    for i in range(len(local_vul)):
        local_vul[i] = local_vul[i].replace('-','_')
    for j in range(len(remote_vul)):
        remote_vul[j] = remote_vul[j].replace('-','_')
    # print(local_vul)
    # print(remote_vul)
    return properties, ports, local_vul, remote_vul

def network_topology(node_number):
    topology = np.zeros([node_number, node_number])
    # The topology matrix can be defined here.
    return topology

def random_topology(node_number):
    topology = np.zeros([node_number, node_number])
    n_u = list(range(node_number))
    for i in range(node_number):
        num = random.randint(1, node_number)
        connect = random.sample(n_u, num)
        for j in connect:
            topology[i, int(j)] = 1
    return topology

def get_random_properties():
    graph = Graph('http://localhost:7474', auth=("neo4j", "qweasd"))
    # print(graph.schema.node_labels) # node label {OS, Vul, Service, Type, Port}
    # print(graph.schema.relationship_types) # relationship type {os, exist, open, type, target1, target2}
    node_matcher = NodeMatcher(graph)
    relationship_matcher = RelationshipMatcher(graph)
    data1 = node_matcher.match('OS').all()
    OS = []
    for data in data1:
        OS.append(data['name'])
    Vul = []
    while len(Vul) == 0:
        node_OS = random.sample(OS, 1)[0]
        node1 = node_matcher.match('OS', name = node_OS).first()
        relationship = list(relationship_matcher.match((None, node1), r_type='os').all())
        for i in relationship:
            Vul.append(i.start_node['CVE_ID'])
        Vul = list(set(Vul))
        if len(Vul) == 0:
            continue
        else:
            # vul_number = random.randint(1, len(Vul))
            # node_vul = random.sample(Vul, vul_number)
            if len(Vul) >= 3:
                node_vul = random.sample(Vul, 2)
            else:
                node_vul = Vul
            Properties = []
            Type = []
            Executable = []
            Score = []
            for v in node_vul:
                node1 = node_matcher.match('Vul', CVE_ID = v).first()
                relationship1 = list(relationship_matcher.match((node1, None), r_type="exist").all())
                relationship2 = list(relationship_matcher.match((node1, None), r_type="type").all())
                relationship3 = list(relationship_matcher.match((node1, None), r_type="target2").all())
                relationship4 = list(relationship_matcher.match((node1, None), r_type="target1").all())
                for i in relationship1:
                    Properties.append(i.end_node['name'])
                for j in relationship2:
                    Type.append(j.end_node['name'])
                for m in relationship3:
                    Executable.append(m.end_node['name'])
                for n in relationship4:
                    Score.append(n.end_node['name'])
            Properties = list(set(Properties))
            # Type = list(set(Type))
            # Executable = list(set(Executable))
            # Score = list(set(Score))
            # print(node_OS)
            # print(node_vul)
            # print(Properties)
            # print(Type)
            # print(Executable)
            # print(Score)
            if len(Properties) >= 2:
                Properties = random.sample(Properties, 2)
            Properties.append(node_OS)
            return node_OS, node_vul, Properties, Type, Executable, Score

def get_vul_cost(vulnerability, score):
    # The vulnerability cost can be defined here.
    costs = []
    for i in range(len(score)):
        if score[i] == 'NULL':
            score[i] = 0
        else:
            score[i] = float(score[i])
    if sum(score) == 0:
        for i in range(len(vulnerability)):
            cost = random.randint(1, 100)
            costs.append(cost)
        return costs
    else:
        costs = [i*100/sum(score) for i in score]
        for i in range(len(score)):
            if costs[i] == 0:
                costs[i] = random.randint(1, 100)
        return costs

def get_vul_rate(vulnerability, executable):
    rates = []
    for i in range(len(vulnerability)):
        if executable[i] == 'NULL':
            rate = str(m.Rates(probingDetectionRate=0.0,  exploitDetectionRate=0.0, successRate=1.0))
            rates.append(rate)
        elif executable[i] == 'y':
            rate = str(m.Rates(probingDetectionRate=0.0, exploitDetectionRate=0.0, successRate=1.0))
            rates.append(rate)
        else:
            rate = str(m.Rates(probingDetectionRate=0.0, exploitDetectionRate=0.0, successRate=1.0))
            rates.append(rate)
    return rates

def get_vul_outcome(vulnerability, topologyi, properties):
    outcomes = []
    VulnerabilityOutcomes = ['LeakedCredentials', 'LeakedNodesId',  'LocalUserEscalation', 'AdminEscalation',
                             'SystemEscalation', 'CustomerData', 'LateralMove', 'ExploitFailed']
    # 'PrivilegeEscalation' contains 'LocalUserEscalation', 'AdminEscalation', 'SystemEscalation'
    connect_node = []
    for i in range(len(topologyi)):
        if topologyi[i] == 1:
            connect_node.append(i)
    c_n = []
    for j in range(len(vulnerability)):
        c_n = list(set(c_n))
        if len(c_n) != len(connect_node) and j == len(vulnerability) - 1:
            other = [str(n) for n in connect_node if n not in c_n]
            outcome = m.LeakedNodesId(other)
            outcomes.append(outcome)
            break
        outcome = random.choice(VulnerabilityOutcomes)
        # print(outcome)
        if outcome == 'LeakedCredentials':
            cre_node = random.sample(connect_node, 1)[0]
            p = random.sample(properties, 1)[0]
            outcome = m.LeakedCredentials(credentials=[m.CachedCredential(node=str(cre_node), port=p,
                                       credential="RandomCreds")])
            c_n.append(cre_node)
            outcomes.append(outcome)
            credential_node.append(str(cre_node))
            credential_port.append(p)
        elif outcome == 'LeakedNodesId':
            num = random.randint(1, len(connect_node))
            c_node = random.sample(connect_node, num)
            c_node_new = [str(c) for c in c_node]
            outcome = m.LeakedNodesId(c_node_new)
            outcomes.append(outcome)
            for cn in c_node:
                c_n.append(cn)
        elif outcome == 'PrivilegeEscalation':
            privilegelevel = ['LocalUser', 'Admin', 'System']
            p_level = random.sample(privilegelevel, 1)
            outcome = m.PrivilegeEscalation(p_level)
            outcomes.append(outcome)
        elif outcome == 'LocalUserEscalation':
            outcome = m.LocalUserEscalation()
            outcomes.append(outcome)
        elif outcome == 'AdminEscalation':
            outcome = m.AdminEscalation()
            outcomes.append(outcome)
        elif outcome == 'SystemEscalation':
            outcome = m.SystemEscalation()
            outcomes.append(outcome)
        elif outcome == 'CustomerData':
            outcome = m.CustomerData()
            outcomes.append(outcome)
        elif outcome == 'LateralMove':
            outcome = m.LateralMove()
            outcomes.append(outcome)
        elif outcome == 'ExploitFailed':
            outcome = m.ExploitFailed()
            outcomes.append(outcome)
    return outcomes

def get_firewall_rule(properties):
    out_num = random.randint(1, len(properties))
    in_num = random.randint(1, len(properties))
    firewall_outgoing = random.sample(properties, out_num)
    firewall_incoming = random.sample(properties, in_num)
    return firewall_outgoing, firewall_incoming

def node_design(node_number):
    nodeInfo = ""
    topology = random_topology(node_number)
    agent_install = []
    for t in range(len(topology)):
        if topology[t,t] == 1:
            agent_install.append(t)
    # print(len(agent_install))
    # if len(agent_install) == 0:
    #     a_i = list(range(len(agent_install)))
    #     random_in = random.choice(agent_install)
    #     topology[random_in, random_in] = 1
    #     agent_install.append(random_in)
    # I1, I2, I3, I4 = default_identifiers()
    I1 = [] # properties
    I2 = [] # port
    I3 = [] # local_vul
    I4 = [] # remote_vul
    Flag_in = False
    for i in range(int(node_number)):
        name0 = str(i)
        os, vul, properties, type, executable, score = get_random_properties()
        costs = get_vul_cost(vul, score)
        rates = get_vul_rate(vul, executable)
        outcomes = get_vul_outcome(vul, topology[i], properties)
        I1.append(os)
        for p in properties:
            I1.append(p)
            I2.append(p)
        for v in range(len(vul)):
            if type[v] == 'LOCAL':
                I3.append(vul[v].replace('-','_'))
            elif type[v] == 'REMOTE':
                I4.append(vul[v].replace('-','_'))
            else:
                print(vul[v], type[v])
        precondition = 0
        vulnerabilities_temp = """{name}=m.VulnerabilityInfo(
                description='{description}',
                type=m.VulnerabilityType.{vulType},
                outcome=m.{outcome},{Other}
                rates=m.{rates},
                URL='{url}',
                reward_string='{rewardString}'
            ),\n            """
        vulnerabilitiesDict = "vulnerabilities=dict(\n\t\t\t"
        for j in range(len(vul)):
            other = ""
            if str(precondition) != "1" and precondition:  # Can modify the conditions for exploiting the vulnerability here.
                other += "\n\t\t\t\t"
                other += "precondition=m.Precondition('{precondition}'),".format(
                    precondition=str(precondition))
            vul[j] = vul[j].replace('-','_')
            if str(outcomes[j])[:7] == 'LeakedC':
                outcomes[j] = str(outcomes[j]).replace('([Cached','(credentials=[m.Cached')
            vulnerabilities_item = vulnerabilities_temp.format(name=vul[j], description=None,
                                                               vulType=type[j], outcome=outcomes[j],
                                                               cost=costs[j], rewardString=None,
                                                               rates=rates[j].replace(",",
                                                                                      ",\n\t\t\t\t\t\t\t "),
                                                               url=None, Other=other)

            vulnerabilitiesDict += vulnerabilities_item

        vulnerabilitiesDict = vulnerabilitiesDict[:-14] + ")"

        outgoing = ""
        incoming = ""
        firewall_outgoing, firewall_incoming = get_firewall_rule(properties)
        for fo in firewall_outgoing:
            outgoing += 'm.FirewallRule("{name}", m.RulePermission.ALLOW),\n\t\t\t\t\t\t' \
                        '\t\t\t\t\t\t   '.format(name=fo)
        # outgoing = outgoing[:-2]

        for fi in firewall_incoming:
            incoming += 'm.FirewallRule("{name}", m.RulePermission.ALLOW),\n\t\t\t\t\t\t' \
                        '\t\t\t\t\t\t   '.format(name=fi)
        # incoming = incoming[:-2]
        firewall = """m.FirewallConfiguration(outgoing=[{outgoing}],
                                         incoming=[{incoming}])""".format(outgoing=outgoing, incoming=incoming)

        nodeInfo_temp = """'{idx}': m.NodeInfo(
        services={services},
        value={value},
        properties={properties},
        agent_installed={agent_installed},
        privilege_level=m.PrivilegeLevel.NoAccess,
        reimagable={reimagable},
        last_reimaging={last_reimaging},
        owned_string='{owned_string}',
        sla_weight={sla_weight},
        firewall={firewall},
        {vulnerabilitiesDict}
    ),"""
        services = []
        for ci in range(len(credential_node)):
            if credential_node[ci] == name0:
                services = """[m.ListeningService("{port}", 
                               allowedCredentials=["RandomCreds"])]""".format(port=credential_port[ci])
        # print(len(credential_node))
        if len(agent_install) > 0:
            if i in agent_install:
                agent_installed = True
                Flag_in = True
            else:
                agent_installed = False
        else:
            # agent_installed = False
            agent_installed = random.random()
            if agent_installed > 0.8:
                agent_installed = True
                Flag_in = True
            else:
                agent_installed = False

        if not Flag_in and i == int(node_number)-1:
            agent_installed = True

        owned_string = ""
        last_reimaging = None
        reimagable = True
        sla_weight = 1.0
        node_item = nodeInfo_temp.format(idx=str(name0), services=services, value=str(random.randint(1, 100)),
                                         properties=str(properties),
                                         agent_installed=str(agent_installed),
                                         reimagable=str(reimagable), sla_weight=str(sla_weight),
                                         last_reimaging=str(last_reimaging),
                                         owned_string=str(owned_string),
                                         vulnerabilitiesDict=vulnerabilitiesDict, firewall=firewall) + '\n\t'
        nodeInfo += node_item
    nodeInfo = nodeInfo[:-1]
    I1 = list(set(I1))
    I2 = list(set(I2))
    I3 = list(set(I3))
    I4 = list(set(I4))
    py_temp = """from simulation import model as m
from simulation.model import Identifiers, NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

identifiers = Identifiers(
                properties=""" + str(I1) + """,
                ports=""" + str(I2) + """,
                local_vulnerabilities=""" + str(I3) + """,
                remote_vulnerabilities=""" + str(I4) + """)

nodes = {
    """ + nodeInfo + """
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=identifiers
    )
    """

    with open('./random2.py', 'w') as file:
        file.write(py_temp)
    file.close()

node_design(15)




