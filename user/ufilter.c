#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "../knetwork.h"

#define NETLINK_USER 31
#define NET_RULES_PATH "/etc/kfilter/netrules"
#define MAX_PAYLOAD sizeof(struct service_ctl)
#define BUF_LEN (10 * (sizeof(struct inotify_event) + PATH_MAX + 1))

// TODO:
// - filter only incoming packets, not outcoming
// - add filtering over port (set rules from cli)
// - add filtering over ip addr (set rules from cli)
// - keep rules in memory for the kernel module, user space read config file
// - calculate stats for ip and port and device
// - integrate logs with grafana
// - watch rules by inotify


static struct msghdr msg; // figure out why it can be in main func stack / i need memory dump HOMEWORK!!

int open_netlink_sock(void) {
    struct sockaddr_nl s_addr;
    int s_fd;

    s_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (s_fd < 0) {
        perror("Unable to open NETLINK socket");
        return -1;
    }

    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = getpid();

    if (bind(s_fd, (struct sockaddr*)&s_addr, sizeof(s_addr))) {
        perror("Unable to bind NETLINK socket");
        return -1;
    };

    return s_fd;
};

struct nlmsghdr* set_nlh(void) {
    struct nlmsghdr* nlh = NULL;
    int nl_msg_size;
    
    nl_msg_size = NLMSG_SPACE(MAX_PAYLOAD);
    // TODO: check if payload is ok from kernel and userland perspective
    nlh = (struct nlmsghdr*) malloc(nl_msg_size);
    if (nlh == NULL) {
        perror("Unable to alloc memory for netlink header");
        return NULL;
    }
    memset(nlh, 0, nl_msg_size);
    nlh->nlmsg_len = nl_msg_size;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    return nlh;
};

void set_msg_hdr(struct nlmsghdr* nlh) {
    static struct sockaddr_nl s_addr;
    static struct iovec iov;

    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = 0;
    s_addr.nl_groups = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    msg.msg_name = (void *)&s_addr;
    msg.msg_namelen = sizeof(s_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
};

int register_subscriber(int fd, struct nlmsghdr* nlh) {
    struct service_ctl sctl;
    struct service_ctl* res_sctl = NULL;

    printf("Registration attempt..\n");
    memcpy(NLMSG_DATA(nlh), &sctl, sizeof(sctl));
    sendmsg(fd, &msg, 0);

    printf("Wait for response..\n");
    recvmsg(fd, &msg, 0);

    res_sctl = (struct service_ctl*)NLMSG_DATA(nlh);
    if (res_sctl->pid == getpid())
        return 0;
    return 1;
}

int main(int argc, char* argv[]) {
    struct nlmsghdr *nlh = NULL;
    struct service_ctl* sctl_resp = NULL;
    struct service_ctl sctl;
    struct net_data* data;
    char buf[BUF_LEN] __attribute__ ((aligned(8)));
    int s_fd, if_fd;
    ssize_t num;

    printf("Initializing inotify..\n");
    if_fd = inotify_init();
    if (if_fd < 0) {
        perror("Unable to initialize inotify\n");
        return 1;
    }

    printf("Opening netlink socket..\n");
    s_fd = open_netlink_sock();
    if (s_fd < 0) {
        return 1;
    }

    nlh = set_nlh();
    if (nlh == NULL) {
        return 1;
    }
    set_msg_hdr(nlh);
    memcpy(NLMSG_DATA(nlh), &sctl, sizeof(sctl));

    if (register_subscriber(s_fd, nlh)) {
        perror("Filter is already sending packtes to different process\n");
        return 1;
    }
    printf("Succeed, waiting for data..\n");

    // first send net rules to kernel
    if (inotify_add_watch(if_fd, NET_RULES_PATH, IN_ALL_EVENTS) < 0) {
        perror("Unable to watch netrules file");
        return 1;
    }
 
    for(;;) {
        num = read(if_fd, buf, BUF_LEN);
        if (num == 0) {
            perror("Fatal");
        }
        if (num < 0) {
            perror("Err");
        }
        fprintf(stderr, "New change");
    };
    // thread or proc to read packages from kernel
    // but share the sockets
    // watch config files
    while(1) {
        // get data
        if (recvmsg(s_fd, &msg, 0) < 0) {
            perror("Unable to get data from kernel");
            continue;
        }
        data = (struct net_data*)NLMSG_DATA(nlh);
        printf("DATA: %s\n", data->if_name);
    };

    free(nlh);
    free(sctl_resp);

    close(s_fd);
    return 0;
}
