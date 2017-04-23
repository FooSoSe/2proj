#include <iostream>
#include <getopt.h>
#include <string.h>

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include <netdb.h>
#include <linux/errqueue.h>

using namespace std;

/* Command Line parameters */
int max_ttl = 30;
int first_ttl = 1;
char * ip_address = nullptr;

void parse_arguments(int argc,char *argv[]);
double deltaT(struct timeval *t1p, struct timeval *t2p);
void usage();   // todo

int main(int argc, char *argv[])
{
    cout << '\0';

    // file descriptor for socket we will use
    int rcv_s_fd;

    const char port[6] = "33434";

    struct addrinfo recv_addr_info, *addr_result;

    /* parse command line arguments */
    parse_arguments(argc, argv);

    memset(&recv_addr_info, '\0', sizeof(struct addrinfo));
    recv_addr_info.ai_family = AF_UNSPEC;
    recv_addr_info.ai_socktype = SOCK_DGRAM;
    recv_addr_info.ai_flags = AI_PASSIVE;
    recv_addr_info.ai_protocol = 0;
    recv_addr_info.ai_canonname = NULL;
    recv_addr_info.ai_addr = NULL;
    recv_addr_info.ai_next = NULL;

    int getaddrinfo_ecode;
    if ((getaddrinfo_ecode = getaddrinfo(ip_address, port, &recv_addr_info, &addr_result)) != 0)
        cerr << "get error code: " << getaddrinfo_ecode << " on getting address info" << endl;

    if ((rcv_s_fd = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol)) < 0)
    {
        cerr << "Error: unknown icmp socket" << endl;
        exit(3);
    }

    char buffer[512], recv_hostname[128];
    struct msghdr msg;      //prijatá správa - môže obsahovať viac control hlavičiek
    struct cmsghdr *cmsg;   //konkrétna control hlavička

    struct timeval timeout;
    fd_set select_fd_set;

    // štruktúra pre adresu kompatibilná s IPv4 aj v6
    struct sockaddr_storage target;

    const char message [6] = "HELLO";

    bool increment_ttl, target_reached = false;

    for (int ttl = first_ttl; ttl <= max_ttl; ++ttl)
    {
        if (target_reached)
            break;

        struct timeval t1, t2;
        struct timezone tz;

        gettimeofday(&t1, &tz);

        increment_ttl = false;

        int hop = ttl;
        int on = 1;

        if (addr_result->ai_family == AF_INET)
        {
            if (setsockopt(rcv_s_fd, IPPROTO_IP, IP_TTL, &hop, sizeof(hop)) < 0)
                perror("setsockopt: ");

            if (setsockopt(rcv_s_fd, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on)) < 0)
                perror("setsockopt: ");
        }
        else if (addr_result->ai_family == AF_INET6)
        {
            if (setsockopt(rcv_s_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hop, sizeof(hop)) < 0)
                perror("setsockopt: ");

            if (setsockopt(rcv_s_fd, SOL_IPV6, IPV6_RECVERR, (char*)&on, sizeof(on)) < 0)
                perror("setsockopt: ");
        }

        /* sending message */
        if(sendto(rcv_s_fd, message, strlen(message), 0, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
            perror("sendto: ");

        for ( ; ; )
        {
            if (increment_ttl || target_reached)
                break;

            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

            msg.msg_name = &target;                 // tu sa uloží cieľ správy, teda adresa nášho stroja
            msg.msg_namelen = sizeof(target);       // obvious
            msg.msg_iov = NULL;                     // ICMP hlavičku reálne nepríjmeme - stačia controll správy
            msg.msg_iovlen = 0;                     // veľkosť štruktúry pre hlavičky - žiadna
            msg.msg_flags = 0;                      // žiadne flagy
            msg.msg_control = buffer;               // predpokladám že buffer pre control správy
            msg.msg_controllen = sizeof(buffer);    // obvious

            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            FD_ZERO(&select_fd_set);                   // vynulujeme štruktúru
            FD_SET(rcv_s_fd, &select_fd_set);          // priradíme socket na ktorom chceme čakať

//            connect(rcv_s_fd, NULL, 0);
            int rs = select(FD_SETSIZE, &select_fd_set, NULL, NULL, &timeout);

            if (rs > 0)
                /* receiving message */
                recvmsg(rcv_s_fd, &msg, MSG_ERRQUEUE);
            else if (rs < 0)
                /* or wait for message connect_to receive */
                continue;

            gettimeofday(&t2, &tz);

            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (increment_ttl || target_reached)
                    break;

                /* skontrolujeme si pôvod správy - niečo podobné nám bude treba aj pre IPv6 */
                if ((cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) || (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR))
                {
                    //získame dáta z hlavičky
                    struct sock_extended_err *e = (struct sock_extended_err *) CMSG_DATA(cmsg);

                    // todo some useful comment
                    if (e && (e->ee_origin == SO_EE_ORIGIN_ICMP || e->ee_origin == SO_EE_ORIGIN_ICMP6))
                    {
                        /* získame adresu - ak to robíte všeobecne tak sockaddr_storage */
                        struct sockaddr_storage *sin = (struct sockaddr_storage *)(e+1);

                        // todo some useful comment
                        getnameinfo((struct sockaddr *) sin, sizeof(sockaddr_storage), recv_hostname, NI_MAXHOST, NULL , 0, NI_NUMERICHOST);

                        cout << ttl << "   " << recv_hostname;

                        if (e->ee_origin == SO_EE_ORIGIN_ICMP)
                        {
                            switch (e->ee_type)
                            {
                                /*
                                * Overíme si všetky možné návratové správy
                                * hlavne ICMP_TIME_EXCEEDED and ICMP_DEST_UNREACH
                                * v prvom prípade inkrementujeme TTL a pokračujeme
                                * v druhom prípade sme narazili na cieľ
                                *
                                * kódy pre IPv4 nájdete tu
                                * http://man7.org/linux/man-pages/man7/icmp.7.html
                                *
                                * kódy pre IPv6 sú ODLIŠNÉ!:
                                * nájdete ich napríklad tu https://tools.ietf.org/html/rfc4443
                                * strana 4
                                */

                                case ICMP_TIME_EXCEEDED:
                                    cout << "   " << deltaT(&t1, &t2) << "ms" << endl;
                                    increment_ttl = true;
                                    break;

                                case ICMP_DEST_UNREACH:
                                    if (e->ee_code == ICMP_NET_UNREACH)
                                        cout << "   N!" << endl;
                                    else if (e->ee_code == ICMP_HOST_UNREACH)
                                        cout << "   H!" << endl;
                                    else if (e->ee_code == ICMP_PROT_UNREACH)
                                        cout << "   P!" << endl;
                                    else if (e->ee_code == ICMP_PKT_FILTERED)
                                        cout << "   X!" << endl;
                                    else if (e->ee_code == ICMP_PORT_UNREACH)
                                    {
                                        cout << "   " << deltaT(&t1, &t2) << "ms" << endl;
                                        target_reached = true;
                                    }
                                    break;

                                default:
                                    cerr << "ee_type not handled!" << endl;
                            }
                        }
                        else
                        {
                            cout << "ee_type: " << e->ee_type;
                            switch (e->ee_type)
                            {
                                /* Echo Request Message */
                                case 129:
                                    cout << "L" << endl;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

void parse_arguments(int argc, char **argv)
{
    int ch;
    while ((ch = getopt(argc, argv, "m:f:")) != EOF)
        switch (ch)
        {
            case 'f':
                first_ttl = atoi(optarg);
                if (first_ttl < 1)
                {
                    cerr << "Error: first ttl must be > 0.\n" << endl;
                    exit(1);
                }
                break;

            case 'm':
                max_ttl = atoi(optarg);
                if (max_ttl <= 1)
                {
                    cerr << "Error: max ttl must be > 1.\n" << endl;
                    exit(1);
                }
                break;

            default:
                usage();
        }

    if (argc < 1)
    {
        usage();
        exit(1);
    }

    argc -= optind;
    argv += optind;

    /* Parsing Ip address from command line */
    if (*argv)
        ip_address = *argv;
}

double deltaT(struct timeval *t1p, struct timeval *t2p)
{
    register double dt;

    dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
         (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
    return (dt);
}

void usage()
{
    cout << "TODO USAGE" << endl;
}