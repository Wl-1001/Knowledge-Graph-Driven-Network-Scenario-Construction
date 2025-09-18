# Knowledge-Graph-Driven-Network-Scenario-Construction

We construct a network knowledge graph for Penetration Testing(PT), and propose an automated network scenario construction method.

## Construction of Network Knowledge Graph

* Ontology Construction
* Data Processing
* Knowledge Graph Building

  Example of the ontology structure

<p align="center">
  <img width="80%" src="./Image/Example of the ontology structure.png">
</p>

## Automated Network Scenario Construction

The node configuration structure is shown in the following figure , encompassing 12 components: Properties, Service, Firewall, Defense Modification, Last Defense Modification, Node Status, Value, Weight, Pwned, Privilege Level, Own String, and Vulnerabilities.

<p align="center">
  <img width="50%" src="./Image/Node configuration structure.png">
</p>


1. Randomly select an OS type from the network knowledge graph, and obtain vulnerability ID information associated with this OS.
2. Randomly select any number of vulnerabilities from the vulnerability IDs as the vulnerabilities existing on the node, and acquire the vulnerability categories as well as the services and their versions related to these vulnerabilities.
3. For each vulnerability on the node, select one result from the vulnerability outcomes as the exploitation result of the vulnerability. It should be noted here that in the exploitation result, the network topology configured during network topology construction needs to be considered, and connections between this node and other nodes can be established through methods such as LeakedNodeId. In addition, if the exploitation result of a vulnerability is to expose credentials of other nodes (i.e., LeakedCredentials), the corresponding credential information must also be configured on the relevant nodes.
4. After completing the settings for all nodes, the construction of the network scenario is finalized.

For a detailed description, please refer to our previous research work  [https://doi.org/10.1016/j.cose.2023.103358](https://doi.org/10.1016/j.cose.2023.103358 "Persistent link using digital object identifier")


## Citation

### Paper

```bibtex
Coming Soon
```
