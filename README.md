# dnssnoop

dnssnoop is a utility for tracing standard DNS queries as they are sent from your system to DNS
servers from all processes on a Linux system in real-time. It captures information related to both
the query made and the resulting response with minimal system overhead.

## Deploying

dnssnoop is a yeet that can be deployed to a yeet daemon using the yeet package manager or directly
from the system running the yeet daemon.

### From YPM

Go to <https://yeet.cx/@yeet/dnssnoop>, select the host on which you'd like it deployed, and click
"Deploy".

### From Source

Build the eBPF program:

    make

Deploy to the local host:

    yeet add .

## Data Schema

Each time a DNS query is made and answered an event is emitted:


| Field | Type | Description |
| ----- | ---- | ----------- |
| tid | `KernelPid` | The thread ID of the thread that made this query. |
| pid | `KernelPid` | The process ID of the process that made this query. |
| uid | `INT` | The user ID of the user that owns the process that made this query. |
| gid | `INT` | The group ID of the user that owns the process that made this query. |
| cgroup_id | `INT` | The ID of the control group associated with the process that made this query. |
| latency_ns | `INT` | The latency, in nanoseconds, between the request and the reply. |
| transaction_id | `INT` | The transaction ID of the query. |
| command | `STRING` | The full command that spawned the process that made this query. |
| thread_name | `STRING` | The name of the thread that made this query. |
| domain_name | `STRING` | The domain name being queried. |
| cgroup_name | `STRING` | The name of the control group associated with the process that made this query. |
| remote_ip | `STRING` | The IP address of the DNS server this query was sent to. |
| remote_port | `INT` | The UDP port of the DNS server this query was sent to. |
| local_ip | `STRING` | The IP address this query was sent from. |
| local_port | `INT` | The UDP port this query was sent from. |

# Examples

## 1. Top 10 Current Slowest Domains by p99 Latency

    SELECT
      event.domain_name,
      ROUND(QUANTILE_CONT(event.latency_ns, 0.99) / 1e6, 2) AS p99_latency_ms
    FROM <collection_name>
    GROUP BY event.domain_name
    ORDER BY p99_latency_ms DESC
    LIMIT 10

### What This Query Does

- Identifies **domains with the slowest DNS resolution times.**
- Helps **optimize performance** by pinpointing DNS bottlenecks.
- Detects **third-party services** affecting **latency and application speed.**
- Surfaces **misconfigured or overloaded DNS resolvers.**
- Prevents **timeouts, slow API responses, and degraded user experiences.**

## 2. Top 10 Most Queried Domains

    SELECT
      event.domain_name,
      COUNT(*) AS total_queries
    FROM <collection_name>
    GROUP BY event.domain_name
    ORDER BY total_queries DESC
    LIMIT 10

### What This Query Does

- Identifies **which domains are queried the most.**
- Helps **analyze DNS traffic patterns** for potential optimizations.
- Detects **unexpected domain spikes** that may indicate security risks or application bugs.

## 3. Top 10 Slowest DNS Resolvers by p99 Latency

    SELECT
      event.remote_ip AS dns_resolver,
      ROUND(QUANTILE_CONT(event.latency_ns, 0.99) / 1e6, 2) AS p99_latency_ms
    FROM <collection_name>
    GROUP BY event.remote_ip
    ORDER BY p99_latency_ms DESC
    LIMIT 10

### What This Query Does

- Finds **the slowest DNS resolvers** that may be affecting performance.
- Helps decide if **switching to a faster resolver (e.g., Cloudflare, Google) is necessary.**
- Detects **network congestion** issues between your system and specific resolvers.

## 4. Top 10 Processes Making the Most DNS Queries

    SELECT
      event.command AS process,
      COUNT(*) AS total_queries
    FROM <collection_name>
    GROUP BY event.command
    ORDER BY total_queries DESC
    LIMIT 10;

### What This Query Does

- Identifies **which processes generate the most DNS traffic.**
- Helps debug **applications or scripts overloading the DNS resolver.**
- Detects **potential malware or suspicious activity.**

## 5. DNS Queries Per Second (Traffic Volume Trend)

    SELECT
      date_trunc('second', timestamp) AS second_bucket,
      COUNT(*) AS queries_per_sec
    FROM <collection_name>
    GROUP BY second_bucket
    ORDER BY second_bucket DESC

### What This Query Does

- Detects **sudden spikes in DNS traffic** (DDoS, botnets, misconfigured services).
- Helps **monitor real-time DNS query load.**
- Useful for **capacity planning and anomaly detection.**

## 6. Least Common DNS Queries.

    SELECT
        event.domain_name,
        COUNT(*) AS query_count
    FROM <collection_name>
    GROUP BY event.domain_name
    ORDER BY query_count ASC

### What This Query Does

- Finds domains that have been **queried the least.**
- **Highlights** one-off lookups, which may indicate: **malware, data exfiltration, misconfigured internal / test domains.**
- Useful for **threat hunting and anomaly detection.**
