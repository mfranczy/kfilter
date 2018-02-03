#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <string.h>

#include "knetwork.h"

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

struct msghdr msg; // figure out why it can be in main func stack / i need memory dump HOMEWORK!!


int main(int argc, char* argv[]) {
    struct sockaddr_nl src_addr, dst_addr;
    struct nlmsghdr *nlh = NULL;
    struct subscriber sub;
    struct iovec iov;
    int s_fd, err;

    s_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (s_fd < 0) {
        printf("Error occured - unable to open NETLINK socket");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    err = bind(s_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (err) {
        printf("Error %d", err);
        return err;
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

    strcpy(NLMSG_DATA(nlh), "REGISTER UFILTER");
    
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
    printf("Recv message: %s\n", (char *)NLMSG_DATA(nlh));

    close(s_fd);

    return 0;
}