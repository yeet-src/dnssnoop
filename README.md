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

### Example Query

You can query a collection from this yeet in the query editor with a query like:

    SELECT
      event.name,
      event.server_ip,
      event.latency_ms,
      event.command,
      timestamp,
      seq_no
    FROM {collection_name}
    ORDER_BY seq_no DESC;
