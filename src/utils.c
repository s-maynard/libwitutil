/*
 * TWC
 * Copyright (C) 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "witutil.h"


static bool use_stderr = false;
static int log_level = DEFAULT_LOG_LEVEL;
static char cpu_arch[MAX_NAME_BUF_SZ];
static char log_fmt[MAX_HTTP_BUF_SZ - 1024];
static char log_buf[MAX_HTTP_BUF_SZ - 256];
static char tx_buf[MAX_HTTP_BUF_SZ];
static char rx_buf[MAX_HTTP_BUF_SZ];


void
log_message(int priority, const char *func, int line, const char *format, ...)
{
    char *str[] = {
        "FATAL", "ALERT", "CRITICAL", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG"
    };
    struct timeval tv;
    unsigned long long current_time;
    va_list vl;

    gettimeofday(&tv, NULL);
    current_time = (unsigned long long)(tv.tv_sec) * 1000 +
                   (unsigned long long)(tv.tv_usec) / 1000;

    if (priority > log_level)
        return;

    snprintf(log_fmt, sizeof(log_fmt), "%llu %-8s- %s, line(%d): %s",
        current_time, str[priority], func, line, format);
    va_start(vl, format);
    vsnprintf(log_buf, sizeof(log_buf), log_fmt, vl);
    va_end(vl);

    if (use_stderr) {
        fprintf(stderr, "\n%s", log_buf);
        fflush(stderr);
    } else {
        syslog(priority, "%s", log_buf);
    }

    if (priority == 0) {
        fprintf(stderr, "\n%s", log_buf);
        fflush(stderr);
	exit(-1);	// exit app on fatal errors
    }
}

bool
parse_get_resp(char *resp, bool is_string, char *str_result, int *int_result)
{
    bool ret_val = false;
    char *data = strstr(resp, "\r\n\r\n");
    char *p = strstr(resp, "\r\n");

    if (NULL == data)
        data = strstr(resp, "\n\n");

    if (NULL == p)
        p = strstr(resp, "\n");

    if (NULL != data && NULL != p) {
        *p = '\0';

        while (*data == '\r' || *data == '\n')
            data++;

        if (strstr(resp, "200 OK")) {
            LOG(INFO,"GET successful");
            ret_val = true;
        } else {
            LOG(WARN,"GET returned unexpected: %s", resp);
        }

        if (is_string) {
            if (NULL != str_result) {
                strcpy(str_result, data);
            } else {
                LOG(ERROR, "str_result == NULL!");
            }
        } else {
            if (NULL != int_result) {
                *int_result = atoi(data);
            }
        }
    } else {
        LOG(ERROR, "can't parse (p=%s, data=%s, resp=%s)", p, data, resp);
    }

    return ret_val;
}

char *
get_mac_str(char *mac)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

#ifndef __APPLE__
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (sock == -1) {
        LOG(ERROR, "socket error");
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        LOG(ERROR, "ioctl SIOCGIFCONF error");
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    // Checking eth0 interface
    strcpy(ifr.ifr_name, "eth0");
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            success = 1;
        }
    }

    // checking for available interface, if eth0 not present
    if (!success) {
    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        } else {
            LOG(ERROR, "ioctl SIOCGIFFLAGS error");
        }
    }
    }

    if (success) {
        sprintf(mac, "%02X%02X%02X_%02X%02X%02X",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    } else {
        sprintf(mac, "%s", "Unknown");
    }

    close(sock);
#else
    sprintf(mac, "010203_040506");
#endif

    return mac;
}

char *
get_ip_str(char* interface, char *ip)
{
    int success = 0;
    struct ifreq ifr;
#ifndef __APPLE__
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
            success = 1;
        }
    }

    close(sock);
#endif
    sprintf(ip, "%s", "0.0.0.0");

    if (success) {
        /* The "inet_ntoa() was deprecated because it does not support IPv6
         * Copy and pasted from a resource site 
         * (pubs.opengroup.org/onlinepubs/009695399/functions/inet_ntop.html):

#include <arpa/inet.h> "In the header"

const char *inet_ntop(int af, const void *restrict src,
       char *restrict dst, socklen_t size);
int inet_pton(int af, const char *restrict src, void *restrict dst);
                 
        */
        sprintf(ip, "%s",
                inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }

    return ip;
}

int
http_send_receive(char *addr, short int port,
                  char *header, char *data, int timeout_secs, char *rx_buf)
{
    struct sockaddr_in servaddr;
    struct hostent *host_addr;
    int sockfd, n, len, bytes;
    struct timeval tv;
    fd_set readfds;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        LOG(ERROR, "socket error");
        return 0;
    }

    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    if (NULL == (host_addr = gethostbyname(addr))) {
        LOG(ERROR, "Unable to locate host");
        return 0;
    }

    //memcpy(&servaddr.sin_addr.s_addr, host_addr->h_addr, host_addr->h_length);
    servaddr.sin_addr.s_addr = *((int*)*host_addr->h_addr_list);
    LOG(DEBUG,"srvr %X:%d", servaddr.sin_addr.s_addr, ntohs(servaddr.sin_port));

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        LOG(ERROR, "connect error");
        return 0;
    }

    bzero(&tx_buf, sizeof(tx_buf));
    snprintf(tx_buf, sizeof(tx_buf), "%s\r\n\r\n%s", header, data);

    /* send the request */
    len = strlen(tx_buf);
    n = 0;

    do {
        bytes = write(sockfd, tx_buf+n, len-n);

        if (bytes < 0) {
            LOG(ERROR, "writing message to socket");
            return 0;
        }
        else if (bytes == 0)
            break;
        else
            n += bytes;
    } while (n < len);

    /* receive the response */
    memset(rx_buf, 0, MAX_HTTP_BUF_SZ);
    len = MAX_HTTP_BUF_SZ-1;
    n = 0;
    tv.tv_sec = timeout_secs;      // wait N.5 seconds for a server response
    tv.tv_usec = 500000;
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(sockfd, &readfds)) {
        do {
            bytes = recv(sockfd, rx_buf+n, len-n, 0);
            if (bytes <= 0)
                break;
            else
                n += bytes;

            LOG(DEBUG, "read %d bytes from socket", bytes);
            usleep(100000);
        } while (n < len);

        if (n == len)
            LOG(ERROR, "storing complete response from socket");
    } else {
        char *p = strstr(header, "HTTP");

        if (p) {
            *p = '\0';	// null terminate command for log...
            LOG(ERROR, "read following %s timed out after %d.5 seconds",
                header, timeout_secs);
            *p = 'H';	// restore HTTP in header after log.
        } else {
            LOG(ERROR, "read timed out after %d.5 seconds", timeout_secs);
        }
    }

    close(sockfd);
    return n;
}

int
send_file(char *addr, short int port, char* post, char* filename, char* rx_buf)
{
    FILE* fd = NULL;
    char* tx_buf = NULL;
    int len = 0;

    if (NULL == (fd = fopen(filename, "rb")))
    {
        LOG(ERROR, "couldn't open %s", filename);
    }
    else
    {
        LOG(INFO, "opened %s", filename);
        fseek(fd, 0, SEEK_END);
        len = ftell(fd);
        fseek(fd, 0, SEEK_SET);
        LOG(INFO, "%d = %s", len, filename);

        if (NULL != (tx_buf = malloc(len+2)))
        {
            bzero(tx_buf, len+2);
            fread(tx_buf, len+1, 1, fd);
            fclose(fd);
            http_post(addr, port, post, "text", tx_buf, rx_buf, 20);
            free(tx_buf);
        }
        else
        {
            LOG(ERROR, "couldn't allocate %d", len+512);
        }
    }

    return len;
}

int
download_file(char *addr, short int port, char *get, char *file, char *rx_buf)
{
    char *data, header[256];
    FILE *fd = NULL;
    int n, bytes = 0;

    snprintf(header, sizeof(header),
        "GET //%s HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Pragma: no-cache\r\n"
        "Connection: keep-alive", get);

    if ((bytes = http_send_receive(addr, port, header, "", 20, rx_buf)) > 0) {
        data = strstr(rx_buf, "\r\n\r\n");

        if (NULL == data)
            data = strstr(rx_buf, "\n\n");

        if (NULL == data) {
            LOG(ERROR, "could not parse response");
            return 0;
        }

        while (*data == '\r' || *data == '\n')  // strip the CRLF
            data++;

        bytes -= (data - rx_buf);               // adjust to data size

        if (bytes && strstr(rx_buf, "200 OK")) {
            LOG(INFO,"Download request successful");

            if (NULL == (fd = fopen(file, "wb"))) {
                LOG(ERROR, "could not open file: %s", file);
            } else if (bytes != (n = fwrite(data, sizeof(char), bytes, fd))) {
                LOG(ERROR, "bytes written (%d) != bytes read (%d)", n, bytes);
                fclose(fd);
            } else {
                LOG(INFO, "wrote %d byte file", n);
                fclose(fd);
            }
        } else {
            LOG(WARN,"Download request failed for: %s", file);
            return 0;
        }
    }

    LOG(INFO, "downloaded %d byte file", bytes);
    return bytes;
}

int
http_get(char *addr, short int port, char *get, char *rx_buf, int timeout)
{
    char header[256];
    int bytes = 0;

    snprintf(header, sizeof(header),
        "GET //%s HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive", get);

    bytes = http_send_receive(addr, port, header, "", timeout, rx_buf);
    rx_buf[bytes] = 0;
    LOG(DEBUG, "rx = %s", rx_buf);
    return bytes;
}

int
http_post(char *addr, short int port,
          char *url, char *type, char *data, char *rx_buf, int timeout)
{
    char header[512];
    int bytes = 0;

    snprintf(header, sizeof(header),
        "POST /%s HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "Accept-Language: en-us\r\n"
        "Content-Type: application/%s\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "User-Agent: Mozilla/4.0\r\n"
        "Content-Length: %zd\r\n"
        "Pragma: no-cache\r\n"
        "Connection: keep-alive", url, type, strlen(data));

    bytes = http_send_receive(addr, port, header, data, timeout, rx_buf);
    rx_buf[bytes] = 0;
    return bytes;
}

int
execute_command(char *cmd, char *res, int size)
{
    char cmd_buf[128];
    bool executed = false;
    FILE *fp;
    char* out = res;
    int sz = size;
    int byte_size = 0;

    if (NULL != cmd) {
        memset(res, '\0', size);
        snprintf(cmd_buf, sizeof(cmd_buf), "%s 2>&1", cmd);

        if(NULL == (fp = popen(cmd_buf, "re"))) {
            LOG(FATAL, "fp == NULL for command %s, errno:%d", cmd_buf, errno);
            return -2;
        }

        while ((byte_size = fread(out, 1, sz, fp)) != 0) {
            executed = true;
            sz -= byte_size;
            out += byte_size;
            if (sz <= 0) {
                break;
            }
        }

        if (pclose(fp) < 0) {
            LOG(ERROR, "pclose fail for command %s, errno:%d", cmd_buf, errno);
        }

        if (!executed) {
            return -1;
        } else {
            return 0;
        }
    }
}

char*
get_cpu_type(void)
{
    FILE *fp;
    size_t bytes_read;
    char *p;

    fp = popen("uname -m", "r");
    bytes_read = fread(cpu_arch, sizeof(char), sizeof(cpu_arch), fp);
    pclose(fp);
    cpu_arch[bytes_read] = '\0';

    if (bytes_read > 0) {
        p = &cpu_arch[bytes_read-1];

        while (*p == '\n' || *p == '\r')
            *p-- = '\0';
    }

    return cpu_arch;
}

int
lockfile(int fd)
{
    struct flock fl;

    // Don't use LOG macros/functions here - called before logging initialized
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;

    return fcntl(fd, F_SETLK, &fl);
}

bool
is_already_running(char const *flock_name)
{
    char buf[16];
    int flock = open(flock_name, O_RDWR | O_CREAT,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    // Don't use LOG macros/functions here - called before logging initialized
    if (flock < 0) {
        fprintf(stderr, "couldn't open lockfile %s (%d)\n", flock_name, flock);
        fprintf(stderr, " - please run as root\n");
        fflush(stderr);
        exit(1);
    } else if (lockfile(flock) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            close(flock);
            return true;
        }

        fprintf(stderr, "couldn't lock lockfile %s (%d)\n", flock_name, flock);
        fprintf(stderr, " - please run as root\n");
        fflush(stderr);
        exit(1);
    }

    if (-1 == ftruncate(flock, 0)) {
        fprintf(stderr, "Failed to truncate: %s\n", strerror(errno));
        fflush(stderr);
        exit(1);
    }

    sprintf(buf, "%ld\n", (long)getpid());

    if (0 == write(flock, buf, strlen(buf) + 1)) {
        fprintf(stderr, "Failed to write: %s\n", flock_name);
        fflush(stderr);
        exit(1);
    }

    return false;
}

void
start_logger(char* logname)
{
    openlog(logname, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
    fprintf(stderr, "logging as: %s\n", logname);
    fflush(stderr);
}

void
stop_logger(void)
{
    closelog();
    fprintf(stderr, "closed syslog\n");
    fflush(stderr);
}

void
set_log_level(int level)
{
    log_level = level;

    if (log_level > DEBUG)
        log_level = DEBUG;
}

void
set_log_stderr(int val)
{
    use_stderr = val;
}

