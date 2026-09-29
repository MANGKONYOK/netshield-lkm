// ==============================================================================
// NetShield-LKM: In-Kernel Network Packet Filter
// Implementation file: Netfilter hook callback, defensive packet inspection,
// anti-lockout fail-safes, dynamic configuration and module lifecycle routines.
// ==============================================================================

#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

#include "netshield.h"

// Module Parameters (Exposed via Sysfs: /sys/module/netshield/parameters/)

static unsigned short block_port = DEFAULT_BLOCK_PORT;
module_param(block_port, ushort, 0644);
MODULE_PARM_DESC(block_port,
                 "Destination TCP port to drop (default: 0 = disabled)");

static bool drop_icmp = DEFAULT_DROP_ICMP;
module_param(drop_icmp, bool, 0644);
MODULE_PARM_DESC(
    drop_icmp,
    "Toggle dropping incoming ICMP echo requests / ping (default: true)");

static char *blacklist_ip = DEFAULT_BLACKLIST_IP;
module_param(blacklist_ip, charp, 0644);
MODULE_PARM_DESC(blacklist_ip,
                 "Source IPv4 address string to block (default: \"\")");

static bool allow_loopback_filter = DEFAULT_ALLOW_LOOPBACK_FILTER;
module_param(allow_loopback_filter, bool, 0644);
MODULE_PARM_DESC(allow_loopback_filter,
                 "Allow filtering on loopback interface 'lo' (default: false "
                 "for anti-lockout)");

/* Netfilter hook operation structure */
static struct nf_hook_ops netshield_ops;

// Netfilter Packet Inspection Hook Callback
// Context: SoftIRQ / Atomic context (NO SLEEP, NO ALLOCATIONS, STRICT O(1))

static unsigned int netshield_hook_func(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
  struct iphdr *iph;
  unsigned int ip_hdr_len;

  // 1. DEFENSIVE SANITY CHECK: skb validation (Zero-Panic Policy)

  if (unlikely(!skb))
    return NF_ACCEPT;

  // 2. ANTI-LOCKOUT: Loopback Traffic Exemption
  // By default, exempt all local IPC and loopback traffic on 'lo'.
  // Can be enabled via 'allow_loopback_filter=1' for local test suites.

  if (!allow_loopback_filter && state && state->in) {
    if (strcmp(state->in->name, "lo") == 0)
      return NF_ACCEPT;
  }

  // 3. DEFENSIVE BOUNDS CHECK: IPv4 Header Verification
  // Ensure packet holds a valid IPv4 header before dereferencing.

  if (unlikely(skb->len < sizeof(struct iphdr)))
    return NF_ACCEPT; /* Truncated buffer: fail-open */

  iph = ip_hdr(skb);
  if (unlikely(!iph))
    return NF_ACCEPT;

  /* Verify minimum header length (ihl: 32-bit words, minimum 5 = 20 bytes) */
  if (unlikely(iph->ihl < 5))
    return NF_ACCEPT;

  ip_hdr_len = iph->ihl * 4;

  /* Ensure packet length is consistent with IP header definition */
  if (unlikely(skb->len < ip_hdr_len))
    return NF_ACCEPT;

  if (unlikely(ntohs(iph->tot_len) < ip_hdr_len))
    return NF_ACCEPT;

  // 4. ANTI-LOCKOUT FAIL-SAFE: Hardcoded SSH Bypass
  // Never drop TCP Port 22 traffic (Source or Destination).
  // Protects active administrator sessions from self-lockout.

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr _tcph;
    const struct tcphdr *tcph;

    tcph = skb_header_pointer(skb, ip_hdr_len, sizeof(_tcph), &_tcph);
    if (tcph &&
        (ntohs(tcph->source) == SSH_PORT || ntohs(tcph->dest) == SSH_PORT)) {
      return NF_ACCEPT; /* Explicit bypass for SSH management */
    }
  }

  // 5. SOURCE IP BLACKLIST FILTERING
  // Match against configured blacklist_ip string.

  if (blacklist_ip && blacklist_ip[0] != '\0') {
    __be32 blocked_ip = 0;
    if (in4_pton(blacklist_ip, -1, (u8 *)&blocked_ip, -1, NULL) > 0) {
      if (iph->saddr == blocked_ip) {
        LOG_DROP_RATELIMITED(
            "Dropped packet from blacklisted IP %pI4 to %pI4 (proto: %u)\n",
            &iph->saddr, &iph->daddr, iph->protocol);
        return NF_DROP;
      }
    }
  }

  // 6. ICMP ECHO REQUEST (PING) FILTERING
  // Drop ping requests when drop_icmp is enabled.
  // Safe header dereference via skb_header_pointer().

  if (drop_icmp && iph->protocol == IPPROTO_ICMP) {
    struct icmphdr _icmph;
    const struct icmphdr *icmph;

    icmph = skb_header_pointer(skb, ip_hdr_len, sizeof(_icmph), &_icmph);
    if (!icmph)
      return NF_ACCEPT; /* Malformed or truncated: fail-open */

    if (icmph->type == ICMP_ECHO) {
      LOG_DROP_RATELIMITED("Dropped ICMP Echo Request from %pI4 to %pI4\n",
                           &iph->saddr, &iph->daddr);
      return NF_DROP;
    }
  }

  // 7. TCP DESTINATION PORT FILTERING
  // Drop packets destined for block_port when configured (> 0).
  // Safe header dereference via skb_header_pointer().

  if (block_port > 0 && iph->protocol == IPPROTO_TCP) {
    struct tcphdr _tcph;
    const struct tcphdr *tcph;

    tcph = skb_header_pointer(skb, ip_hdr_len, sizeof(_tcph), &_tcph);
    if (!tcph)
      return NF_ACCEPT; /* Truncated or inaccessible: fail-open */

    if (ntohs(tcph->dest) == block_port) {
      LOG_DROP_RATELIMITED(
          "Dropped TCP packet destined for port %u from %pI4 to %pI4\n",
          block_port, &iph->saddr, &iph->daddr);
      return NF_DROP;
    }
  }

  // 8. DEFAULT POLICY: FAIL-OPEN
  // Unmatched or authorized traffic is forwarded unimpeded.

  return NF_ACCEPT;
}

// Module Initialization Routine

static int __init netshield_init(void) {
  int ret;

  LOG_INFO("Initializing %s v%s\n", NETSHIELD_NAME, NETSHIELD_VERSION);

  LOG_INFO("Configuration: block_port=%u, drop_icmp=%s, blacklist_ip='%s', "
           "allow_loopback_filter=%s\n",
           block_port, drop_icmp ? "true" : "false", blacklist_ip,
           allow_loopback_filter ? "true" : "false");

  /* Audit provided blacklist IP parameter format if non-empty */
  if (blacklist_ip && blacklist_ip[0] != '\0') {
    __be32 test_ip = 0;
    if (in4_pton(blacklist_ip, -1, (u8 *)&test_ip, -1, NULL) <= 0) {
      LOG_WARN(
          "Invalid blacklist_ip format '%s'. Blacklist rule will not match.\n",
          blacklist_ip);
    } else {
      LOG_INFO("Active IP blacklist filter target: %pI4\n", &test_ip);
    }
  }

  /* Configure Netfilter hook operations */
  netshield_ops.hook = netshield_hook_func;
  netshield_ops.hooknum = NF_INET_LOCAL_IN;
  netshield_ops.pf = NFPROTO_IPV4;
  netshield_ops.priority = NF_IP_PRI_FIRST;

  /* Register Netfilter hook with init network namespace */
  ret = nf_register_net_hook(&init_net, &netshield_ops);
  if (ret < 0) {
    LOG_ERR("Failed to register Netfilter hook (error %d)\n", ret);
    return ret;
  }

  LOG_INFO("Netfilter hook successfully registered at NF_INET_LOCAL_IN "
           "(Priority: NF_IP_PRI_FIRST).\n");
  return 0;
}

// Module Cleanup Routine
// Synchronous teardown: Unregister hook before any resource deallocations

static void __exit netshield_exit(void) {
  /* Unregister Netfilter hook immediately to stop incoming packet dispatch */
  nf_unregister_net_hook(&init_net, &netshield_ops);

  LOG_INFO("%s unloaded successfully. Netfilter hook unregistered.\n",
           NETSHIELD_NAME);
}

module_init(netshield_init);
module_exit(netshield_exit);

/* Module Metadata & Legal Attribution */
MODULE_LICENSE(NETSHIELD_LICENSE);
MODULE_AUTHOR(NETSHIELD_AUTHOR);
MODULE_DESCRIPTION(NETSHIELD_DESC);
MODULE_VERSION(NETSHIELD_VERSION);