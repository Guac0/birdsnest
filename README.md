# Stabvest Evolved
Stabvest Evolved is a next-generation service integrity management tool designed for operations in a contested security environment. It keeps business-critical services online with automated reactions to malicious interference while keeping human operators informed for incident response efforts. During all this, it operates with a minimal-trust mindset designed to enable resilency to malicious counteractions while not unduly limiting the information available to human operators.

## Stabvest Server
The Server provides a web-based central aggregator node for agents to report their status and observed malicious actions to. Human operators can utilize the website GUI tool to monitor for agent compliance and to act on observed incidents of malicious activity or log source drop offs. Additionally, the Server enables limited remote interaction with agents in a minimal trust environment, as well as easy deployment of new agents.

## Stabvest Agents
The
The Agent is not directly remotely accessible for security reasons.

## Stabvest Agent Helper
The Agent Helper provides a streamlined way for systems administrators to interact with Agents on a machine, allowing them to temporarily pause Agent operations while maintenance tasks are carried out on protected services and files. For security reasons, the Helper does not assist in removing or permanently stopping any Agent services, and may require the operator to use information stored by the Server's data aggregation to identify specific agents present on the local machine. The Helper is not directly remotely accessible for security reasons.