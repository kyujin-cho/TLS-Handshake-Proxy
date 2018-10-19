#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <unistd.h>

struct addr_type {
  long ip;
  int port;
};

struct addr_type get_original_addr(int fd) {
  struct sockaddr_in original_addr;
  struct addr_type return_val;
  return_val.port = -1;

  int struct_size = sizeof(struct sockaddr_in);
  if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &original_addr, &struct_size) != 0) {
    perror("getsockopt");
    return return_val;
  } 
  if(original_addr.sin_family != AF_INET) {
    dprintf(STDERR_FILENO, "getsockopt returns unknown family!");
    return return_val;
  }
  int port = ntohs(original_addr.sin_port);
  return_val.ip = original_addr.sin_addr.s_addr;
  return_val.port = port;
  return return_val;
}
