#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "knetwork.h"

#define NETLINK_USER 31
#define MAX_PAYLOAD sizeof(struct service_ctl)

// TODO:
// - filter only incoming packets, not outcoming
// - add filtering over port (set rules from cli)
// - add filtering over ip addr (set rules from cli)
// - keep rules in memory for the kernel module, user space read config file
// - calculate stats for ip and port and device
// - integrate logs with grafana


struct msghdr msg; // figure out why it can be in main func stack / i need memory dump HOMEWORK!!


int main(int argc, char* argv[]) {
    struct sockaddr_nl src_addr, dst_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct service_ctl sctl;
    struct service_ctl* sctl_resp;
    struct net_data* data;
    int s_fd, rc;

    s_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (s_fd < 0) {
        printf("error occured - unable to open NETLINK socket");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    rc = bind(s_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (rc) {
        printf("Error %s", strerror(errno));
        return rc;
    }

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strncpy(sctl.msg, "REGISTRATION REQUEST", MAX_SERVICE_MSG_SIZE);
    memcpy(NLMSG_DATA(nlh), &sctl, sizeof(sctl));
 
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1; 

    printf("Sending register msg to kfilter\n");
    sendmsg(s_fd, &msg, 0);
    printf("Message has been sent\n");
    recvmsg(s_fd, &msg, 0);
    printf("Let's work");

    sctl_resp = (struct service_ctl*)NLMSG_DATA(nlh);
    if (sctl_resp->pid == getpid()) {
        // thread or proc to read packages from kernel
        // but share the sockets
        // watch config files
        while(1) {
            // get data
            rc = recvmsg(s_fd, &msg, 0);
            if (rc == -1) {
                printf("Error: %s", strerror(errno));
                continue;
            }
            data = (struct net_data*)NLMSG_DATA(nlh);
            printf("DATA: %s\n", data->if_name);

        };
    } else {
        printf("Module is already sending packets to pid: %d", sctl_resp->pid);
    }
    close(s_fd);

    return 0;
}
