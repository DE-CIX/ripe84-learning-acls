# Learning DDoS Filtering Rules from IXP Blackholing Traffic with Association Rule Mining

This repository contains supplemental material for our upcoming ACM SIGCOMM '22 paper. If you use this work, please cite as follows:

> M. Wichtlhuber, E. Strehle, D. Kopp, L. Prepens, S. Stegmueller, A. Rubina, C. Dietzel, O. Hohlfeld. 2022. "IXP
Scrubber: Learning from Blackholing Traffic for ML-Driven DDoS Detection at Scale." In Proceedings of ACM SIGCOMM 2022 Conference (SIGCOMM ’22; accepted for publication).

The material was also presented at the anti-abuse WG meeting at RIPE84 Berlin 2022 in a more light-weight form (see [RIPE84 video archive](https://ripe84.ripe.net/archives/video/821/) or slides below).

## Contents

* *ddos_acls.pdf* - the slides of the talk held during the RIPE WG meeting.
* *rules_0.9.json* - the list of filtering rules in JSON format as described in the presentation/the paper. All mined filtering rules with a confidence of 90% and higher are contained. This set was used for the evaluation section of the paper.

## Filter rule list JSON format

The list is provided in the following JSON format:

```
"0a42ee90": {                # A unique identifier
 "protocol":17,              # The protocol IANA code
 "port_src":123,             # The L4 transport source port IANA code
 "port_dst":28960,           # The L4 destination port IANA code
 "packet_size":"(400,500]",  # Packet size interval - "(" inclusive border, "]" exclusive border
 "confidence":0.99,          # Probability with which this packet header is blackholed with RTBH [1]
 "antecedent support":1021,  # This rule was mined based on 1021 flows
}
```

There are a number of special values:

* Each field can be encoded as a wildcard (`"*"`) carrying a match any semantics.
* If port_src and port_dst are both set to 0, this indicates fragmented traffic of the relevant protocol.
* Notably, protocol, port_src, port_dst, can also be encoded as exclusive sets: "~{0,17,19,21,25,53,69,80,111}"; the semantics of this encoding is that none of the above encoded values should be matched. If you generate ACLs for networking gear, you can replace exclusive sets with a wildcard (`"*"`).

## Rule statistics

The mined rules represent a list of the packet headers most likely to be blackholed. A large share of the rules cover DNS as DNS is hard to filter as it is frequently used legitimately and constitutes one of the very basic protocols keeping the Internet running. The top 10 covered sending L4 ports are shown below:

<img src="stats_per_src_port.png" width="50%">

A shown below, 80% of the ACLs have a >96% confidence of being blackholed.

<img src="confidence_distribution.png" width="50%">

# Contributions

We are happy to accept contributions. In particular, if you create scripts for converting the JSON list into an ACL list for your networking gear, feels free to create a pull request.
