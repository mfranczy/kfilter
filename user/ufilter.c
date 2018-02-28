#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/inotify.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "../knetwork.h"

#define NETLINK_USER 31
#define NET_RULES_PATH "/etc/kfilter/netrules"
#define MAX_PAYLOAD 1024
#define BUF_LEN (10 * (sizeof(struct inotify_event) + PATH_MAX + 1))

// TODO:
// - REFACTORING - CHECK SEG FAULT!
// - filter only incoming packets, not outcoming
// - add filtering over port (set rules from cli)
// - add filtering over ip addr (set rules from cli)
// - keep rules in memory for the kernel module, user space read config file
// - calculate stats for ip and port and device
// - integrate logs with grafana
// - watch rules by inotify (nice to have)


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

int send_net_rules(int fd, struct nlmsghdr* nlh, struct net_rules* n_rules) {
    memcpy(NLMSG_DATA(nlh), n_rules, sizeof(struct net_rules));
    sendmsg(fd, &msg, 0);
    return 0;
}

void set_netrules(struct net_rules* n_rules) {
    FILE* fp = NULL;
    char* rule = NULL;
    char* token = NULL;
    char proto[4];
    size_t len = 0;
    ssize_t read;
    int i = 0, j = 0;

    fp = fopen(NET_RULES_PATH, "r");
    if (fp == NULL) {
        perror("Unable to read netrules..\n");
        return;
    }
    
    // this is so so so bad, refactoring needed!
    // only for test now
    while((read = getline(&rule, &len, fp)) > 0) {
        j = 0;
        printf("%s", rule);
        // sound like recursion
        while ((token = strsep(&rule, ":")) != NULL || j < 3) {
            if (j == 0) {
                strncpy(proto, token, 3);
            }
            if (strcmp(proto, "TCP") == 0) {
                if (j == 1) {
                    n_rules->t_rules.rules_cnt++;
                    inet_pton(AF_INET, token, &n_rules->t_rules.r[i].addr);
                } else if (j == 2) {
                    n_rules->t_rules.r[i].port = strtoul(token, (char**)NULL, 10);
                }
            } else if (strcmp(proto, "UDP") == 0) {
                if (j == 1) {
                    n_rules->u_rules.rules_cnt++;
                    inet_pton(AF_INET, token, &n_rules->u_rules.r[i].addr);
                } else if (j == 2) {
                    n_rules->u_rules.r[i].port = strtoul(token, (char**)NULL, 10);
                }
            }
            j++;
        }
        i++;
    }

    fclose(fp);
}

int main(int argc, char* argv[]) {
    struct nlmsghdr *nlh = NULL;
    struct net_rules n_rules = {
        .t_rules = {
            .rules_cnt = 0
        },
        .u_rules = {
            .rules_cnt = 0
        }
    };
    struct net_data* data;
    char buf[BUF_LEN] __attribute__ ((aligned(8)));
    int s_fd;
    ssize_t num;

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

    if (register_subscriber(s_fd, nlh)) {
        perror("Filter is already sending packtes to different process\n");
        return 1;
    }
    free(nlh);

    nlh = set_nlh();
    if (nlh == NULL) {
        return 1;
    }
    set_msg_hdr(nlh);

    printf("Reading net rules..\n\n");
    set_netrules(&n_rules);
    free(nlh);

    printf("\nSending net rules to kernel module..\n");
    if (send_net_rules(s_fd, nlh, &n_rules)) {
        perror("Unable to send net rules");
        return 1;
    }

    printf("Succeed, waiting for data..\n");

    while(1) {
        // get data
        if (recvmsg(s_fd, &msg, 0) < 0) {
            perror("Unable to get data from kernel");
            continue;
        }
        data = (struct net_data*)NLMSG_DATA(nlh);
        printf("DATA: %s\n", data->if_name);
    };

    close(s_fd);
    return 0;
}
