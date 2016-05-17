/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __WITUTIL_H__
#define __WITUTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>

#define MAX_HTTP_BUF_SZ (1024*1024)
#define MAX_NAME_BUF_SZ 128

#define FATAL  0
#define ALERT  LOG_ALERT
#define CRIT   LOG_CRIT
#define ERROR  LOG_ERR
#define WARN   LOG_WARNING
#define NOTICE LOG_NOTICE
#define INFO   LOG_INFO
#define DEBUG  LOG_DEBUG

#define DEFAULT_LOG_LEVEL LOG_INFO

#define LOG(priority, format, ...) \
    log_message(priority, __func__, __LINE__, format, ##__VA_ARGS__)

extern void log_message(int priority, const char *func, int line,
                        const char *format, ...);
extern bool parse_get_resp(char *resp, bool is_string, char *str_result,
                           int *int_result);
extern char* get_mac_str(char *mac);
extern char* get_ip_str(char* interface, char *ip);
extern int http_send_receive(char *addr, short int port, char *header,
                             char *data, int timeout_secs, char *rx_buf);
extern int send_file(char *addr, short int port, char* post, char* file,
                     char* rx_buf);
extern int download_file(char *addr, short int port, char *get, char *file,
                         char *rx_buf);
extern int http_get(char *addr, short int port, char *get, char *rx_buf,
                    int timeout);
extern int http_post(char *addr, short int port, char *url, char *type,
                     char *data, char *rx_buf, int timeout);
extern int execute_command(char *cmd, char *res, int size);
extern char* get_cpu_type(void);
extern int lockfile(int fd);
extern bool is_already_running(char const *flock_name);
extern void set_log_level(int level);
extern void set_log_stderr(int val);
extern void start_logger(char* logname);
extern void stop_logger(void);

#endif
