strace-analyzer
===============



This tool is designed to analyze strace log for potential performance issue with any appications on Linux. The log should be created
with command "strace -ttT" as we heavily rely on the time spent in each system call.



If your application is heavy in network traffic, the tool  list the most noisy file descriptors for both inbound and outbound traffic.

If your application is heavy in disk IO, the tool draws a graph showing the overral read()/write() response time trend for each file descriptor.




====
TODO

The time gap between two adjcent epoll_wait() calls is a good resource to tell how long it takes to run each epoll loop.
