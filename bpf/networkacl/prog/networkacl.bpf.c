// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Ant Group Corporation.

#include <uapi.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define ACL_ALLOW 1
#define ACL_DENY 2

#define ACL_INGRESS 1
#define ACL_EGRESS 2

#define POLICY_STATEFUL 2

#define RULE_MATCH_PEER_ANY 0x01
#define RULE_MATCH_VALID 0x80

#define MAX_POLICY_RULES 256

#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define IPV4_MORE_FRAGMENTS 0x2000

#define PROTOCOL_ICMP 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12

struct acl_icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 unused;
            __be16 mtu;
        } frag;
    } un;
};

struct acl_ports {
    __be16 source;
    __be16 destination;
};

#define NSEC_PER_SEC 1000000000ULL
#define TCP_TIMEOUT_NS (24ULL * 60 * 60 * NSEC_PER_SEC)
#define TCP_CLOSING_TIMEOUT_NS (30ULL * NSEC_PER_SEC)
#define UDP_TIMEOUT_NS (180ULL * NSEC_PER_SEC)
#define ICMP_TIMEOUT_NS (30ULL * NSEC_PER_SEC)
#define FRAGMENT_TIMEOUT_NS (30ULL * NSEC_PER_SEC)

struct policy_value {
    __u64 generation;
    __be32 sandbox_ip;
    __u8 traffic_enabled;
    __u8 traffic_default;
    __u8 dns_enabled;
    __u8 mode;
};

struct policy_v2_rule {
    __be32 peer_ip;
    __u32 priority;
    __u16 peer_port_first;
    __u16 peer_port_last;
    __u16 sandbox_port_first;
    __u16 sandbox_port_last;
    __u8 peer_prefix;
    __u8 action;
    __u8 directions;
    __u8 protocol;
    __u8 match_flags;
    __u8 reserved[3];
};

struct policy_v2_value {
    __u64 generation;
    __be32 sandbox_ip;
    __u16 rule_count;
    __u8 traffic_enabled;
    __u8 ingress_default;
    __u8 egress_default;
    __u8 dns_enabled;
    __u8 mode;
    __u8 update_barrier;
    __u8 reserved[4];
    struct policy_v2_rule rules[MAX_POLICY_RULES];
};

struct domain_policy_key {
    __u64 generation;
    __u32 ifindex;
    __be32 peer_ip;
};

struct domain_policy_rule {
    __u64 expires_at;
    __u32 priority;
    __u16 peer_port_first;
    __u16 peer_port_last;
    __u16 sandbox_port_first;
    __u16 sandbox_port_last;
    __u8 action;
    __u8 protocol;
    __u8 reserved[2];
};

struct domain_policy_value {
    __u16 rule_count;
    __u8 reserved[6];
    struct domain_policy_rule rules[MAX_POLICY_RULES];
};

/* Keep this structure 24 bytes and retain the legacy field offsets. */
struct rule_key {
    __u64 generation;
    __u32 ifindex;
    __be32 peer_ip;
    __be16 peer_port;
    __u8 direction;
    __u8 protocol;
    __be16 sandbox_port;
    __u8 match_flags;
    __u8 reserved;
};

struct connection_key {
    __u64 generation;
    __u32 ifindex;
    __be32 peer_ip;
    __be16 peer_port;
    __be16 sandbox_port;
    __u8 protocol;
    __u8 reserved[3];
};

struct connection_value {
    __u64 expires_at;
    /* Zero for static rules, otherwise the DNS-derived grant deadline. */
    __u64 authorization_expires_at;
};

struct fragment_key {
    __u64 generation;
    __u32 ifindex;
    __be32 source_ip;
    __be32 destination_ip;
    __be16 identification;
    __u8 protocol;
    __u8 direction;
};

struct fragment_value {
    __u64 expires_at;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} POLICY_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rule_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} RULE_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct policy_v2_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} POLICY_V2_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct domain_policy_key);
    __type(value, struct domain_policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} DOMAIN_V2_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct connection_key);
    __type(value, struct connection_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    /* Versioned because v2 adds the authorization expiry field. */
} CONN_V2_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fragment_key);
    __type(value, struct fragment_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} FRAGMENT_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} CONFIG_MAP SEC(".maps");

struct action_result {
    __u64 expires_at;
    __u32 priority;
    __u8 action;
    bool matched;
};

static __always_inline bool port_matches(__u16 port, __u16 first, __u16 last)
{
    return first == 0 || (port >= first && port <= last);
}

static __always_inline bool cidr_matches(__be32 peer_ip, __be32 network, __u8 prefix)
{
    __u32 host_peer;
    __u32 host_network;
    __u32 mask;

    if (prefix >= 32)
        return peer_ip == network;
    if (prefix == 0)
        return true;
    host_peer = bpf_ntohl(peer_ip);
    host_network = bpf_ntohl(network);
    mask = 0xffffffffU << (32 - prefix);
    return (host_peer & mask) == (host_network & mask);
}

static __always_inline void consider_action(struct action_result *result, __u8 action,
                                            __u32 priority, __u64 expires_at)
{
    if (!result->matched || priority > result->priority ||
        (priority == result->priority && action == ACL_DENY)) {
        result->matched = true;
        result->priority = priority;
        result->action = action;
        result->expires_at = expires_at;
    }
}

struct static_rule_context {
    struct policy_v2_value *policy;
    struct action_result result;
    __be32 peer_ip;
    __u16 peer_port;
    __u16 sandbox_port;
    __u8 direction;
    __u8 protocol;
};

static long inspect_static_rule(__u32 index, void *opaque)
{
    struct static_rule_context *context = opaque;
    struct policy_v2_rule *rule;
    volatile __u8 bounded_index;

    if (index >= MAX_POLICY_RULES)
        return 1;
    bounded_index = (__u8)index;
    if (bounded_index >= context->policy->rule_count)
        return 1;
    rule = &context->policy->rules[bounded_index];
    if (!(rule->directions & context->direction))
        return 0;
    if (rule->protocol != 0 && rule->protocol != context->protocol)
        return 0;
    if (!(rule->match_flags & RULE_MATCH_PEER_ANY) &&
        !cidr_matches(context->peer_ip, rule->peer_ip, rule->peer_prefix))
        return 0;
    if (!port_matches(context->peer_port, rule->peer_port_first, rule->peer_port_last) ||
        !port_matches(context->sandbox_port, rule->sandbox_port_first, rule->sandbox_port_last))
        return 0;
    consider_action(&context->result, rule->action, rule->priority, 0);
    return 0;
}

static __always_inline void inspect_static_rules(struct policy_v2_value *policy, __u8 direction,
                                                 __u8 protocol, __be32 peer_ip, __u16 peer_port,
                                                 __u16 sandbox_port, struct action_result *result)
{
    struct static_rule_context context = {
        .policy = policy,
        .result = *result,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .sandbox_port = sandbox_port,
        .direction = direction,
        .protocol = protocol,
    };

    bpf_loop(MAX_POLICY_RULES, inspect_static_rule, &context, 0);
    *result = context.result;
}

struct domain_rule_context {
    struct domain_policy_value *policy;
    struct action_result result;
    __u64 now;
    __u16 peer_port;
    __u16 sandbox_port;
    __u8 protocol;
};

static long inspect_domain_rule(__u32 index, void *opaque)
{
    struct domain_rule_context *context = opaque;
    struct domain_policy_rule *rule;
    volatile __u8 bounded_index;

    if (index >= MAX_POLICY_RULES)
        return 1;
    bounded_index = (__u8)index;
    if (bounded_index >= context->policy->rule_count)
        return 1;
    rule = &context->policy->rules[bounded_index];
    if (rule->expires_at < context->now)
        return 0;
    if (rule->protocol != 0 && rule->protocol != context->protocol)
        return 0;
    if (!port_matches(context->peer_port, rule->peer_port_first, rule->peer_port_last) ||
        !port_matches(context->sandbox_port, rule->sandbox_port_first, rule->sandbox_port_last))
        return 0;
    consider_action(&context->result, rule->action, rule->priority, rule->expires_at);
    return 0;
}

static __always_inline void inspect_domain_rules(struct policy_v2_value *policy, __u32 ifindex,
                                                 __u8 protocol, __be32 peer_ip, __u16 peer_port,
                                                 __u16 sandbox_port, __u64 now,
                                                 struct action_result *result)
{
    struct domain_policy_key key = {
        .generation = policy->generation,
        .ifindex = ifindex,
        .peer_ip = peer_ip,
    };
    struct domain_policy_value *value = bpf_map_lookup_elem(&DOMAIN_V2_MAP, &key);
    struct domain_rule_context context;

    if (!value)
        return;
    context.policy = value;
    context.result = *result;
    context.now = now;
    context.peer_port = peer_port;
    context.sandbox_port = sandbox_port;
    context.protocol = protocol;
    bpf_loop(MAX_POLICY_RULES, inspect_domain_rule, &context, 0);
    *result = context.result;
}

static __always_inline struct action_result
rule_action(struct policy_v2_value *policy, __u32 ifindex, __u8 direction, __u8 protocol,
            __be32 peer_ip, __be16 peer_port, __be16 sandbox_port, __u64 now)
{
    struct action_result result = {};
    __u16 host_peer_port = bpf_ntohs(peer_port);
    __u16 host_sandbox_port = bpf_ntohs(sandbox_port);

    inspect_static_rules(policy, direction, protocol, peer_ip, host_peer_port, host_sandbox_port,
                         &result);
    if (direction == ACL_EGRESS)
        inspect_domain_rules(policy, ifindex, protocol, peer_ip, host_peer_port, host_sandbox_port,
                             now, &result);
    if (!result.matched)
        result.action = direction == ACL_INGRESS ? policy->ingress_default : policy->egress_default;
    return result;
}

static __always_inline struct connection_key connection_key(struct policy_v2_value *policy,
                                                            __u32 ifindex, __be32 peer_ip,
                                                            __be16 peer_port, __be16 sandbox_port,
                                                            __u8 protocol)
{
    struct connection_key key = {
        .generation = policy->generation,
        .ifindex = ifindex,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .sandbox_port = sandbox_port,
        .protocol = protocol,
    };
    return key;
}

static __always_inline bool connection_allowed(struct connection_key *key, __u64 now, __u64 refresh,
                                               __u64 *allowed_until)
{
    struct connection_value *value = bpf_map_lookup_elem(&CONN_V2_MAP, key);
    struct connection_value next;

    if (!value || value->expires_at < now)
        return false;
    if (refresh != 0) {
        next = *value;
        next.expires_at = now + refresh;
        if (next.authorization_expires_at != 0 && next.authorization_expires_at < next.expires_at)
            next.expires_at = next.authorization_expires_at;
        bpf_map_update_elem(&CONN_V2_MAP, key, &next, BPF_ANY);
        *allowed_until = next.expires_at;
    } else {
        *allowed_until = value->expires_at;
    }
    return true;
}

static __always_inline void remember_connection(struct connection_key *key, __u64 expires_at,
                                                __u64 authorization_expires_at)
{
    struct connection_value value = {
        .expires_at = expires_at,
        .authorization_expires_at = authorization_expires_at,
    };
    bpf_map_update_elem(&CONN_V2_MAP, key, &value, BPF_ANY);
}

static __always_inline struct fragment_key
fragment_key(struct policy_v2_value *policy, __u32 ifindex, struct iphdr *iph, __u8 direction)
{
    struct fragment_key key = {
        .generation = policy->generation,
        .ifindex = ifindex,
        .source_ip = iph->saddr,
        .destination_ip = iph->daddr,
        .identification = iph->id,
        .protocol = iph->protocol,
        .direction = direction,
    };
    return key;
}

static __always_inline bool fragment_allowed(struct fragment_key *key, __u64 now)
{
    struct fragment_value *value = bpf_map_lookup_elem(&FRAGMENT_MAP, key);
    return value && value->expires_at >= now;
}

static __always_inline void remember_fragment(struct fragment_key *key, __u64 now,
                                              __u64 allowed_until)
{
    struct fragment_value value = {.expires_at = now + FRAGMENT_TIMEOUT_NS};

    if (allowed_until != 0 && allowed_until < value.expires_at)
        value.expires_at = allowed_until;
    bpf_map_update_elem(&FRAGMENT_MAP, key, &value, BPF_ANY);
}

static __always_inline bool related_icmp(void *l4, void *data_end, struct policy_v2_value *policy,
                                         __u32 ifindex, __u8 direction, __u64 now,
                                         __u64 *allowed_until)
{
    struct acl_icmphdr *icmp = l4;
    struct iphdr *inner;
    void *inner_l4;
    __be32 peer_ip;
    __be16 peer_port = 0;
    __be16 sandbox_port = 0;
    struct connection_key key;

    if ((void *)(icmp + 1) > data_end)
        return false;
    if (icmp->type != ICMP_DEST_UNREACH && icmp->type != ICMP_TIME_EXCEEDED &&
        icmp->type != ICMP_PARAMETERPROB)
        return false;
    inner = (void *)(icmp + 1);
    if ((void *)(inner + 1) > data_end || inner->version != 4 || inner->ihl < 5)
        return false;
    inner_l4 = (void *)inner + ((__u32)inner->ihl * 4);
    if (inner_l4 > data_end)
        return false;

    if (direction == ACL_INGRESS) {
        if (inner->saddr != policy->sandbox_ip)
            return false;
        peer_ip = inner->daddr;
        if (inner->protocol == PROTOCOL_TCP || inner->protocol == PROTOCOL_UDP) {
            struct acl_ports *ports = inner_l4;
            if ((void *)(ports + 1) > data_end)
                return false;
            sandbox_port = ports->source;
            peer_port = ports->destination;
        } else {
            return false;
        }
    } else {
        if (inner->daddr != policy->sandbox_ip)
            return false;
        peer_ip = inner->saddr;
        if (inner->protocol == PROTOCOL_TCP || inner->protocol == PROTOCOL_UDP) {
            struct acl_ports *ports = inner_l4;
            if ((void *)(ports + 1) > data_end)
                return false;
            peer_port = ports->source;
            sandbox_port = ports->destination;
        } else {
            return false;
        }
    }
    key = connection_key(policy, ifindex, peer_ip, peer_port, sandbox_port, inner->protocol);
    return connection_allowed(&key, now, 0, allowed_until);
}

static __always_inline int enforce(struct __sk_buff *skb, __u8 direction)
{
    __u32 ifindex = skb->ifindex;
    struct policy_v2_value *policy = bpf_map_lookup_elem(&POLICY_V2_MAP, &ifindex);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    void *l4;
    struct fragment_key frag_key;
    struct connection_key conn_key;
    __be32 peer_ip;
    __be16 peer_port = 0;
    __be16 sandbox_port = 0;
    __u8 protocol;
    __u16 fragment;
    __u64 now = bpf_ktime_get_ns();
    __u64 refresh = 0;
    __u64 allowed_until = 0;
    __u32 config_key = 0;
    __be32 *bridge_ip;
    bool first_fragment;
    bool create_connection = false;
    struct action_result decision;

    if (!policy || (!policy->traffic_enabled && !policy->dns_enabled))
        return TC_ACT_OK;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return TC_ACT_OK;
    if (policy->update_barrier)
        return TC_ACT_SHOT;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_SHOT;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl < 5)
        return TC_ACT_SHOT;
    l4 = (void *)iph + ((__u32)iph->ihl * 4);
    if (l4 > data_end)
        return TC_ACT_SHOT;

    if (direction == ACL_EGRESS) {
        if (iph->saddr != policy->sandbox_ip)
            return TC_ACT_SHOT;
        peer_ip = iph->daddr;
    } else {
        if (iph->daddr != policy->sandbox_ip)
            return TC_ACT_SHOT;
        peer_ip = iph->saddr;
    }
    protocol = iph->protocol;
    fragment = bpf_ntohs(iph->frag_off);
    frag_key = fragment_key(policy, ifindex, iph, direction);
    if ((fragment & IPV4_FRAGMENT_OFFSET_MASK) != 0)
        return fragment_allowed(&frag_key, now) ? TC_ACT_OK : TC_ACT_SHOT;
    first_fragment = (fragment & IPV4_MORE_FRAGMENTS) != 0;

    if (protocol == PROTOCOL_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_SHOT;
        peer_port = direction == ACL_EGRESS ? tcp->dest : tcp->source;
        sandbox_port = direction == ACL_EGRESS ? tcp->source : tcp->dest;
        refresh = (tcp->fin || tcp->rst) ? TCP_CLOSING_TIMEOUT_NS : TCP_TIMEOUT_NS;
        create_connection = tcp->syn && !tcp->ack;
    } else if (protocol == PROTOCOL_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_SHOT;
        peer_port = direction == ACL_EGRESS ? udp->dest : udp->source;
        sandbox_port = direction == ACL_EGRESS ? udp->source : udp->dest;
        refresh = UDP_TIMEOUT_NS;
        create_connection = true;
    } else if (protocol == PROTOCOL_ICMP) {
        struct acl_icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > data_end)
            return TC_ACT_SHOT;
        if (policy->mode == POLICY_STATEFUL &&
            related_icmp(l4, data_end, policy, ifindex, direction, now, &allowed_until)) {
            if (first_fragment)
                remember_fragment(&frag_key, now, allowed_until);
            return TC_ACT_OK;
        }
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            peer_port = icmp->un.echo.id;
            refresh = ICMP_TIMEOUT_NS;
            create_connection = icmp->type == ICMP_ECHO;
        }
    }

    if (policy->dns_enabled && (protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) &&
        peer_port == bpf_htons(53)) {
        bridge_ip = bpf_map_lookup_elem(&CONFIG_MAP, &config_key);
        if (!bridge_ip || peer_ip != *bridge_ip)
            return TC_ACT_SHOT;
        if (first_fragment)
            remember_fragment(&frag_key, now, 0);
        return TC_ACT_OK;
    }

    if (!policy->traffic_enabled) {
        if (first_fragment)
            remember_fragment(&frag_key, now, 0);
        return TC_ACT_OK;
    }

    conn_key = connection_key(policy, ifindex, peer_ip, peer_port, sandbox_port, protocol);
    if (policy->mode == POLICY_STATEFUL && refresh != 0 &&
        connection_allowed(&conn_key, now, refresh, &allowed_until)) {
        if (first_fragment)
            remember_fragment(&frag_key, now, allowed_until);
        return TC_ACT_OK;
    }

    /* ICMP identifiers are state only; ICMP policy rules do not match ports. */
    decision = rule_action(policy, ifindex, direction, protocol, peer_ip,
                           protocol == PROTOCOL_ICMP ? 0 : peer_port, sandbox_port, now);
    if (decision.action != ACL_ALLOW)
        return TC_ACT_SHOT;

    if (policy->mode == POLICY_STATEFUL && create_connection && refresh != 0) {
        __u64 expires_at = now + refresh;

        if (decision.expires_at != 0 && decision.expires_at < expires_at)
            expires_at = decision.expires_at;
        remember_connection(&conn_key, expires_at, decision.expires_at);
    }
    if (first_fragment)
        remember_fragment(&frag_key, now, decision.expires_at);
    return TC_ACT_OK;
}

SEC("tc/sandboxd_acl_egress")
int sandboxd_acl_egress(struct __sk_buff *skb) { return enforce(skb, ACL_EGRESS); }

SEC("tc/sandboxd_acl_ingress")
int sandboxd_acl_ingress(struct __sk_buff *skb) { return enforce(skb, ACL_INGRESS); }
