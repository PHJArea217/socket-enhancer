#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <dlfcn.h>
struct ipv6_with_scope {
	struct in6_addr address;
	uint32_t scope_id;
};
static int parse_ipv6_with_scope(char *str, struct ipv6_with_scope *result) {
	char *percent_brk = strchr(str, '%');
	if (percent_brk) {
		char *interface_name = &percent_brk[1];
		*percent_brk = 0;
		uint32_t index;
		if ((interface_name[0] >= '0') && (interface_name[0] <= '9')) {
			index = strtoul(interface_name, NULL, 0);
		} else {
			index = if_nametoindex(interface_name);
			if (!index) return -1;
		}
		struct in6_addr res_addr = {0};
		if (inet_pton(AF_INET6, str, &res_addr) != 1) return -1;
		result->scope_id = index;
		memcpy(&result->address, &res_addr, sizeof(struct in6_addr));
	} else {
		int results = inet_pton(AF_INET6, str, &result->address);
		if (results != 1) return -1;
		result->scope_id = 0;
	}
	return 0;
}
struct socket_enhancer_config {
	int (*real_bind)(int, const struct sockaddr *, socklen_t);
	int (*real_connect)(int, const struct sockaddr *, socklen_t);
	struct in_addr ipv4_default;
	struct in_addr ipv4_loopback;
	uint8_t universal_link_local_mode;
	uint8_t always_freebind;
	uint8_t has_v4_default:1;
	uint8_t has_v4_loopback:1;
	uint8_t has_v6_default:1;
	uint8_t has_v6_v4mapv6:1;
	uint8_t has_v6_linklocal:1;
	uint8_t has_v6_uniquelocal:1;
	struct ipv6_with_scope ipv6_default;
	struct ipv6_with_scope ipv6_v4mapv6;
	struct ipv6_with_scope ipv6_linklocal;
	struct ipv6_with_scope ipv6_uniquelocal;
};
static struct socket_enhancer_config *global_config = NULL;
static void parse_v4(const char *addr, struct in_addr *result) {
	if (inet_pton(AF_INET, addr, result) != 1) {
		fprintf(stderr, "Invalid IPv4 address %s\n", addr);
		abort();
	}
}
static void parse_v6(char *addr, struct ipv6_with_scope *result) {
	if (parse_ipv6_with_scope(addr, result)) {
		fprintf(stderr, "Invalid IPv6 address %s\n", addr);
		abort();
	}
}
__attribute__((constructor))
static void socket_enhancer_init(void) {
	void *real_bind_p = dlsym(RTLD_NEXT, "bind");
	if (!real_bind_p) abort();
	void *real_connect_p = dlsym(RTLD_NEXT, "connect");
	if (!real_connect_p) abort();
	struct socket_enhancer_config *temp_config = calloc(sizeof(struct socket_enhancer_config), 1);
	if (!temp_config) abort();
	temp_config->real_bind = real_bind_p;
	temp_config->real_connect = real_connect_p;
	const char *config_str = getenv("SOCKET_ENHANCER_CONFIG");
	if (config_str) {
		char *dup_configstr = strdup(config_str);
		if (!dup_configstr) abort();
		char *saveptr = NULL;
		for (char *token = strtok_r(dup_configstr, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
			if (strnlen(token, 5) < 5) {
				fprintf(stderr, "Invalid config option %s\n", token);
				abort();
				return;
			}
			if (token[4] != '=') {
				fprintf(stderr, "Config option must be name=value\n");
				abort();
				return;
			}
			uint32_t option = ntohl(*(uint32_t *) token);
			token[4] = 0;
			char *value = &token[5];
			unsigned long option_numeric_value = 0;
			switch (option) {
				case 0x69707634: /* "ipv4" */
					parse_v4(value, &temp_config->ipv4_default);
					temp_config->has_v4_default = 1;
					break;
				case 0x76346c62: /* "v4lb" */
					parse_v4(value, &temp_config->ipv4_loopback);
					temp_config->has_v4_loopback = 1;
					break;
				case 0x69707636: /* "ipv6" */
					parse_v6(value, &temp_config->ipv6_default);
					temp_config->has_v6_default = 1;
					break;
				case 0x76366c6c: /* "v6ll" */
					parse_v6(value, &temp_config->ipv6_linklocal);
					temp_config->has_v6_linklocal = 1;
					break;
				case 0x76346d36: /* "v4m6" */
					parse_v6(value, &temp_config->ipv6_v4mapv6);
					temp_config->has_v6_v4mapv6 = 1;
					break;
				case 0x76367571: /* "v6uq" */
					parse_v6(value, &temp_config->ipv6_uniquelocal);
					temp_config->has_v6_uniquelocal = 1;
					break;
				case 0x7636756c: /* "v6ul" */
					option_numeric_value = strtoul(value, NULL, 0);
					if (option_numeric_value > 3) goto out_of_range;
					temp_config->universal_link_local_mode = option_numeric_value;
					break;
				case 0x66726562: /* "freb" */
					option_numeric_value = strtoul(value, NULL, 0);
					if (option_numeric_value > 3) goto out_of_range;
					temp_config->always_freebind = option_numeric_value;
					break;
				default:
					fprintf(stderr, "Invalid config option %s\n", token);
					abort();
					return;
			}
			continue;
out_of_range:
			fprintf(stderr, "Value %lu for %s out of range\n", option_numeric_value, token);
			abort();
			return;
		}
		free(dup_configstr);
	}
	__atomic_store_n(&global_config, temp_config, __ATOMIC_SEQ_CST);
}
static void convert_universal_linklocal(struct sockaddr_in6 *addr) {
	if (!addr->sin6_scope_id) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		if (addr->sin6_addr.s6_addr32[0] == 0x000090fe) {
			addr->sin6_addr.s6_addr32[0] = 0x000080fe;
#else
		if (addr->sin6_addr.s6_addr32[0] == 0xfe900000) {
			addr->sin6_addr.s6_addr32[0] = 0xfe800000;
#endif
			addr->sin6_scope_id = ntohl(addr->sin6_addr.s6_addr32[1]);
			addr->sin6_addr.s6_addr32[1] = 0;
		}
	}
#if 0
}
#endif
}
static int try_preconnect_bind_v4(int fd, const struct in_addr *bind_addr, int freebind, struct socket_enhancer_config *config) {
	struct sockaddr_in existing_address = {0};
	socklen_t addrlen = sizeof(struct sockaddr_in);
	if (getsockname(fd, (struct sockaddr *) &existing_address, &addrlen)) return -1;
	if (addrlen == sizeof(struct sockaddr_in)) {
		if (existing_address.sin_family == AF_INET) {
			if (*(uint32_t *) &existing_address.sin_addr) return 0;
		}
	}
	int one = 1;
	setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
	one = 1;
	if (freebind) setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one));
	memset(&existing_address, 0, sizeof(existing_address));
	existing_address.sin_family = AF_INET;
	memcpy(&existing_address.sin_addr, bind_addr, sizeof(struct in_addr));
	return config->real_bind(fd, (struct sockaddr *) &existing_address, sizeof(existing_address));
}
static int try_preconnect_bind_v6(int fd, const struct ipv6_with_scope *bind_addr, int freebind, struct socket_enhancer_config *config) {
	struct sockaddr_in6 existing_address = {0};
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	if (getsockname(fd, (struct sockaddr *) &existing_address, &addrlen)) return -1;
	if (addrlen == sizeof(struct sockaddr_in6)) {
		if (existing_address.sin6_family == AF_INET6) {
			if (existing_address.sin6_addr.s6_addr32[0]) return 0;
			if (existing_address.sin6_addr.s6_addr32[1]) return 0;
			if (existing_address.sin6_addr.s6_addr32[2]) return 0;
			if (existing_address.sin6_addr.s6_addr32[3]) return 0;
		}
	}
	int one = 1;
	setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
	one = 1;
	if (freebind) setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one));
	memset(&existing_address, 0, sizeof(existing_address));
	existing_address.sin6_family = AF_INET6;
	memcpy(&existing_address.sin6_addr, &bind_addr->address, sizeof(struct in6_addr));
	existing_address.sin6_scope_id = bind_addr->scope_id;
	return config->real_bind(fd, (struct sockaddr *) &existing_address, sizeof(existing_address));
}
int connect(int fd, const struct sockaddr *addr_, socklen_t len_) {
	if (!addr_) {
		errno = EFAULT;
		return -1;
	}
	const struct sockaddr *addr = addr_;
	socklen_t len = len_;
	union {
		struct sockaddr_in ipv4_addr;
		struct sockaddr_in6 ipv6_addr;
	} new_addr;
	memset(&new_addr, 0, sizeof(new_addr));
	struct socket_enhancer_config *config = __atomic_load_n(&global_config, __ATOMIC_SEQ_CST);
	if (!config) abort();
	int always_freebind = !!(config->always_freebind & 2);
	if (len == sizeof(struct sockaddr_in6)) {
		if (addr->sa_family == AF_INET6) {
			const struct ipv6_with_scope *bind_addr = NULL;
			struct ipv6_with_scope tmp_addr = {0};
			memcpy(&new_addr.ipv6_addr, addr, sizeof(struct sockaddr_in6));
			addr = (struct sockaddr *) &new_addr.ipv6_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&new_addr.ipv6_addr.sin6_addr)) {
				if (config->universal_link_local_mode & 2) {
					convert_universal_linklocal(&new_addr.ipv6_addr);
				}
				if (config->has_v6_linklocal) {
					bind_addr = &config->ipv6_linklocal;
					if (IN6_IS_ADDR_UNSPECIFIED(&bind_addr->address) && bind_addr->scope_id) {
						if (!new_addr.ipv6_addr.sin6_scope_id) {
							new_addr.ipv6_addr.sin6_scope_id = bind_addr->scope_id;
						}
						bind_addr = NULL;
					}
				} else if (config->has_v6_default) {
					bind_addr = &config->ipv6_default;
				}
			} else if (IN6_IS_ADDR_V4MAPPED(&new_addr.ipv6_addr.sin6_addr)) {
				if (config->has_v6_v4mapv6) {
					bind_addr = &config->ipv6_v4mapv6;
				} else if (config->has_v4_default) {
					tmp_addr.address.s6_addr16[4] = 0;
					tmp_addr.address.s6_addr16[5] = 0xffff;
					tmp_addr.address.s6_addr32[3] = *(uint32_t *) &config->ipv4_default;
					bind_addr = &tmp_addr;
				}
			} else if ((new_addr.ipv6_addr.sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
				if (config->has_v6_uniquelocal) {
					bind_addr = &config->ipv6_uniquelocal;
				} else if (config->has_v6_default) {
					bind_addr = &config->ipv6_default;
				}
			} else {
				if (config->has_v6_default) {
					bind_addr = &config->ipv6_default;
				}
			}
			if (bind_addr) {
				if (try_preconnect_bind_v6(fd, bind_addr, always_freebind, config)) return -1;
			}
		}
	} else if (len == sizeof(struct sockaddr_in)) {
		if (addr->sa_family == AF_INET) {
			memcpy(&new_addr.ipv4_addr, addr, sizeof(struct sockaddr_in));
			addr = (struct sockaddr *) &new_addr.ipv4_addr;
			struct in_addr *v4_address = &new_addr.ipv4_addr.sin_addr;
			if ((config->has_v4_loopback) && ((ntohl(v4_address->s_addr) & 0xff000000) == 0x7f000000)) {
				if (try_preconnect_bind_v4(fd, &config->ipv4_loopback, always_freebind, config)) return -1;
			} else if (config->has_v4_default) {
				if (try_preconnect_bind_v4(fd, &config->ipv4_default, always_freebind, config)) return -1;
			}
		}
	}
	return config->real_connect(fd, addr, len);
}
int bind(int fd, const struct sockaddr *addr_, socklen_t len_) {
	if (!addr_) {
		errno = EFAULT;
		return -1;
	}
	struct socket_enhancer_config *config = __atomic_load_n(&global_config, __ATOMIC_SEQ_CST);
	if (!config) abort();
	int always_freebind = !!(config->always_freebind & 1);
	const struct sockaddr *addr = addr_;
	socklen_t len = len_;
	struct sockaddr_in6 ipv6_addr = {0};
	if (len == sizeof(struct sockaddr_in6)) {
		if (addr->sa_family == AF_INET6) {
			memcpy(&ipv6_addr, addr, sizeof(struct sockaddr_in6));
			addr = (struct sockaddr *) &ipv6_addr;
			if (config->universal_link_local_mode & 1) {
				convert_universal_linklocal(&ipv6_addr);
			}
		}
	}
	if (always_freebind) {
		int one = 1;
		setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one));
	}
	return config->real_bind(fd, addr, len);
}
