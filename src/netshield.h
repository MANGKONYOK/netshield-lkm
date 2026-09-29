// ==============================================================================
// NetShield-LKM: In-Kernel Network Packet Filter
// Header file: Declarations, constants and logging macros.
// ==============================================================================

#ifndef _NETSHIELD_H
#define _NETSHIELD_H

#include <linux/types.h>

/* Module metadata definitions */
#define NETSHIELD_NAME "netshield"
#define NETSHIELD_VERSION "1.0"
#define NETSHIELD_AUTHOR "Shishiron"
#define NETSHIELD_DESC "In-Kernel Network Packet Filter LKM using Netfilter"
#define NETSHIELD_LICENSE "GPL"

/* Unified kernel logging prefix */
#define NETSHIELD_LOG_PREFIX "[NetShield-LKM]: "

/* Kernel logging helpers */
#define LOG_INFO(fmt, ...) pr_info(NETSHIELD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) pr_warn(NETSHIELD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) pr_err(NETSHIELD_LOG_PREFIX fmt, ##__VA_ARGS__)

/* Rate-limited drop logger to prevent dmesg/disk exhaustion (Zero-Panic /
 * Anti-DoS) */
#define LOG_DROP_RATELIMITED(fmt, ...)                                         \
  do {                                                                         \
    if (net_ratelimit())                                                       \
      pr_info(NETSHIELD_LOG_PREFIX fmt, ##__VA_ARGS__);                        \
  } while (0)

/* Anti-Lockout Fail-Safe: Hardcoded SSH Management Port */
#define SSH_PORT 22

/* Default module parameter values */
#define DEFAULT_BLOCK_PORT 0
#define DEFAULT_DROP_ICMP true
#define DEFAULT_BLACKLIST_IP ""
#define DEFAULT_ALLOW_LOOPBACK_FILTER false

#endif /* _NETSHIELD_H */