from py2neo import Graph, Node, Relationship, NodeMatcher
import csv
# 连接neo4j数据库，输入地址、用户名、密码 #修改
graph = Graph("bolt://localhost:7687",auth=("", ""))
graph.delete_all() #清除neo4j中原有的结点等所有信息

with open(r"./cve_for_neo4j.csv", 'r') as f:
    reader = csv.reader(f)
    data = list(reader)
# print(data[1])
#[CVE_ID	Vul_type	OS	OS_verison	Service	Service_version	Port	Execuable	CVSS】

for i in range(1,len(data)):
    
    matcher = NodeMatcher(graph)

    #漏洞 Vul
    if matcher.match('Vul',CVE_ID = data[i][0]):
        node = matcher.match('Vul',CVE_ID = data[i][0]).first()
    else:
        node = Node('Vul',CVE_ID = data[i][0])
        graph.create(node)

    #漏洞类型 Type 关系：Vul——type——Type
    if matcher.match('Type',name = data[i][1]):
        relation = matcher.match('Type',name = data[i][1]).first()
        graph.create(Relationship(node, 'type', relation))
    else:
        relation = Node('Type',name = data[i][1])
        graph.create(relation)
        graph.create(Relationship(node, 'type', relation))

    #操作系统类型
    # if matcher.match('OS',name = data[i][2]):
    #     relation1 = matcher.match('OS',name = data[i][2]).first()
    # else:
    #     relation1 = Node('OS',name = data[i][2])
    #     graph.create(relation1)

    #操作系统及版本 OS 关系：Vul——os——OS
    os_versions = data[i][3].split('\n')
    for ver in os_versions:
        # print(ver)
        if matcher.match('OS',name = ver):
            relation2 = matcher.match('OS',name = ver).first()
            graph.create(Relationship(node, 'os', relation2))
            # graph.create(Relationship(relation2, '属于', relation1))
        else:
            relation2 = Node('OS',name = ver)
            graph.create(relation2)
            graph.create(Relationship(node, 'os', relation2))
            # graph.create(Relationship(relation2, '属于', relation1))
    
    #服务类型
    # if matcher.match('Service',name = data[i][4]):
    #     relation3 = matcher.match('Service',name = data[i][4]).first()
    #     graph.create(Relationship(node, '服务', relation3))
    # else:
    #     relation3 = Node('Service',name = data[i][4])
    #     graph.create(relation3)
    #     graph.create(Relationship(node, '服务', relation3))

    #服务及版本Service 关系：Vul——exist——Service
    ser_versions = data[i][5].split('\n')
    for ser in ser_versions:
        # print(ser)
        if matcher.match('Service',name = ser):
            relation4 = matcher.match('Service',name = ser).first()
            graph.create(Relationship(node, 'exist', relation4))
            # graph.create(Relationship(relation4, '属于', relation3))
        else:   
            relation4 = Node('Service',name = ser)
            graph.create(relation4)
            graph.create(Relationship(node, 'exist', relation4))
            # graph.create(Relationship(relation4, '属于', relation3))

    #端口 Port 关系：Vul——open——Port
    if matcher.match('Port',name = data[i][6]):
        relation5 = matcher.match('Port',name = data[i][6]).first()
        graph.create(Relationship(node, 'open', relation5))
    else:
        relation5 = Node('Port',name = data[i][6])
        graph.create(relation5)
        graph.create(Relationship(node, 'open', relation5))
    

    # 是否可利用
    if matcher.match('Executable',name = data[i][7]):
        relation6 = matcher.match('Executable',name = data[i][7]).first()
        graph.create(Relationship(node, 'target2', relation6))
    else:
        relation6 = Node('Executable',name = data[i][7])
        graph.create(relation6)
        graph.create(Relationship(node, 'target2', relation6))
    
    #CVSS评分
    if matcher.match('Score',name = data[i][8]):
        relation7 = matcher.match('Score',name = data[i][8]).first()
        graph.create(Relationship(node, 'target1', relation7))
    else:
        relation7 = Node('Score',name = data[i][8])
        graph.create(relation7)
        graph.create(Relationship(node, 'target1', relation7))
