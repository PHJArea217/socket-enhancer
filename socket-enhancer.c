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
#include <unistd.h>
struct ipv6_with_scope {
	struct in6_addr address;
	uint32_t scope_id;
};
struct bind_profile {
	uint16_t idx;
	uint8_t has_if:1;
	uint8_t has_if_name:1;
	uint8_t has_fwmark:1;
	uint8_t set_transparent:1;
	uint8_t has_bind_address:1;
	uint32_t fwmark;
	union {
		char *ifname;
		uint32_t ifindex;
	} bind_interface;
	struct in6_addr bind_address;
};
struct socket_enhancer_config {
	int (*real_bind)(int, const struct sockaddr *, socklen_t);
	int (*real_connect)(int, const struct sockaddr *, socklen_t);
	int (*real_socket)(int, int, int);
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
	uint8_t has_bp_high:1;
	struct ipv6_with_scope ipv6_default;
	struct ipv6_with_scope ipv6_v4mapv6;
	struct ipv6_with_scope ipv6_linklocal;
	struct ipv6_with_scope ipv6_uniquelocal;
	struct bind_profile *bind_profile_head;
	size_t bind_profile_size;
};
static int handle_bind_profile(int socket_fd, const struct bind_profile *profile, int do_bind_address, uint16_t port, struct socket_enhancer_config *config) {
	if (profile->has_fwmark) {
		if (setsockopt(socket_fd, SOL_SOCKET, SO_MARK, &profile->fwmark, sizeof(uint32_t))) return -1;
	}
	if (profile->set_transparent) {
		int one = 1;
		if (setsockopt(socket_fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one))) {
			return -1;
		}
	}
	if (profile->has_if) {
		if (profile->has_if_name) {
			if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, profile->bind_interface.ifname, strlen(profile->bind_interface.ifname) + 1)) {
				return -1;
			}
		} else {
			if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTOIFINDEX, &profile->bind_interface.ifindex, sizeof(uint32_t))) {
				return -1;
			}
		}
	}
	if (do_bind_address && profile->has_bind_address) {
		if (port == 0) {
			int one = 1;
			setsockopt(socket_fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
		}
		struct sockaddr_in new_bind_addr = {};
		struct sockaddr_in6 new_bind_addr6 = {};
		int sock_type = AF_UNSPEC;
		socklen_t sock_type_len = sizeof(int);
		if (getsockopt(socket_fd, SOL_SOCKET, SO_DOMAIN, &sock_type, &sock_type_len)) return -1;
		if (sock_type_len != sizeof(int)) return -1;
		switch (sock_type) {
			case AF_INET:
				if (IN6_IS_ADDR_V4MAPPED(&profile->bind_address)) {
					new_bind_addr.sin_family = AF_INET;
					new_bind_addr.sin_port = port;
					new_bind_addr.sin_addr.s_addr = profile->bind_address.s6_addr32[3];
					if (config->real_bind(socket_fd, (struct sockaddr *) &new_bind_addr, sizeof(new_bind_addr))) return -1;
				} else {
					errno = EADDRNOTAVAIL;
					return -1;
				}
				break;
			case AF_INET6:
				new_bind_addr6.sin6_family = AF_INET6;
				new_bind_addr6.sin6_port = port;
				memcpy(&new_bind_addr6.sin6_addr, &profile->bind_address, sizeof(struct in6_addr));
				if (config->real_bind(socket_fd, (struct sockaddr *) &new_bind_addr6, sizeof(new_bind_addr6))) return -1;
				break;
			default:
				errno = ENOPROTOOPT;
				return -1;
		}
	}
	return 0;
}
static int compare_bind_profiles(const void *first, const void *second) {
	struct bind_profile *a = (struct bind_profile *) first;
	struct bind_profile *b = (struct bind_profile *) second;
	if (a->idx < b->idx) return -1;
	else if (a->idx > b->idx) return 1;
	else return 0;
}
static struct bind_profile *find_bind_profile_by_index(struct socket_enhancer_config *config, uint16_t idx) {
	struct bind_profile dummy = {.idx = idx};
	return bsearch(&dummy, config->bind_profile_head, config->bind_profile_size, sizeof(struct bind_profile), compare_bind_profiles);
}
static int get_idx_by_address(const struct sockaddr *addr, socklen_t len) {
	uint32_t ipv4_address = 0;
	if ((len == sizeof(struct sockaddr_in6)) && (addr->sa_family == AF_INET6)) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
			ipv4_address = ntohl(addr6->sin6_addr.s6_addr32[3]);
			goto ipv4;
#if __BYTE_ORDER == __LITTLE_ENDIAN
		} else if ((addr6->sin6_addr.s6_addr32[0] == 0x00808ffeU)
#else
		} else if ((addr6->sin6_addr.s6_addr32[0] == 0xfe8f8000U)
#endif
			&& (addr6->sin6_addr.s6_addr32[1] == 0U) && (addr6->sin6_addr.s6_addr32[2] == 0U) && (addr6->sin6_addr.s6_addr16[6] == 0U)) {
			uint16_t idxval_r = ntohs(addr6->sin6_addr.s6_addr16[7]);
			if (idxval_r & 0x8000U) {
				return idxval_r;
			}
		} else if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) return 63;
		else if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) return 61;
		else return 60;
	} else if ((len == sizeof(struct sockaddr_in)) && (addr->sa_family == AF_INET)) {
		const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
		ipv4_address = ntohl(addr4->sin_addr.s_addr);
		goto ipv4;
	}
	return -1;
ipv4:
	if ((ipv4_address & 0xffffc000U) == 0x7fa74000U) {
		return 0x4000U | (ipv4_address & 0x4000U);
	} else if ((ipv4_address & 0xff000000U) == 0x7f000000U) {
		return 41;
	} else {
		return 40;
	}
}
static int apply_bind_profile(int socket_fd, uint16_t idx, uint16_t port, struct socket_enhancer_config *config, int do_bind) {
	struct bind_profile *profile = find_bind_profile_by_index(config, idx);
	if (profile) {
		if (handle_bind_profile(socket_fd, profile, do_bind, port, config)) return -1;
		return 1;
	}
	if ((idx >= 16384) && config->has_bp_high) {
		errno = EADDRNOTAVAIL;
		return -1;
	}
	return 0;
}
static int apply_bind_profile_sockname(int socket_fd, const struct sockaddr *addr, socklen_t len, struct socket_enhancer_config *config, int do_bind) {
	int profile_idx = get_idx_by_address(addr, len);
	if (profile_idx < 0) return 0;
	if ((len == sizeof(struct sockaddr_in6)) && (addr->sa_family == AF_INET6)) {
		return apply_bind_profile(socket_fd, profile_idx, ((struct sockaddr_in6 *) addr)->sin6_port, config, do_bind);
	} else if ((len == sizeof(struct sockaddr_in)) && (addr->sa_family == AF_INET)) {
		return apply_bind_profile(socket_fd, profile_idx, ((struct sockaddr_in *) addr)->sin_port, config, do_bind);
	}
	return 0;
}
static int parse_bind_profile_string(const char *input_string, struct bind_profile *result) {
	memset(result, 0, sizeof(struct bind_profile));
	char *saveptr = NULL;
	char *input_string_d = strdup(input_string);
	if (!input_string_d) return -1;
	char *idx_str = strtok_r(input_string_d, "/", &saveptr);
	if (!idx_str) goto out;
	unsigned long idx_num = strtoul(idx_str, NULL, 0);
	if ((idx_num == 0) || (idx_num > 65535)) goto out;
	result->idx = idx_num;
	while (1) {
		char *token = strtok_r(NULL, "/", &saveptr);
		if (!token) break;
		switch (token[0]) {
			case 'M':
				if (result->has_fwmark) goto out;
				errno = 0;
				unsigned long fwmark = strtoul(&token[1], NULL, 0);
				if (errno || (fwmark > 4294967295UL)) goto out;
				result->has_fwmark = 1;
				result->fwmark = fwmark;
				break;
			case 'D':
				if (result->has_if) goto out;
				char *ifname = strdup(&token[1]);
				if (!ifname) goto out;
				result->bind_interface.ifname = ifname;
				result->has_if = 1;
				result->has_if_name = 1;
				break;
			case 'I':
				if (result->has_if) goto out;
				errno = 0;
				unsigned long ifindex = strtoul(&token[1], NULL, 0);
				if (errno || (ifindex > 4294967295UL)) goto out;
				result->bind_interface.ifindex = ifindex;
				result->has_if = 1;
				result->has_if_name = 0;
				break;
			case 'T':
				result->set_transparent = 1;
				break;
			case 'B':
				if (result->has_bind_address) goto out;
				if (strchr(&token[1], ':')) {
					if (inet_pton(AF_INET6, &token[1], &result->bind_address) != 1) goto out;
				} else {
					result->bind_address.s6_addr32[0] = 0;
					result->bind_address.s6_addr32[1] = 0;
					result->bind_address.s6_addr16[4] = 0;
					result->bind_address.s6_addr16[5] = 0xffffU;
					if (inet_pton(AF_INET, &token[1], &result->bind_address.s6_addr32[3]) != 1) goto out;
				}
				result->has_bind_address = 1;
				break;
			default:
				goto out;
		}
	}
	free(input_string_d);
	return 0;
out:
	if (result->has_if_name) free(result->bind_interface.ifname);
	free(input_string_d);
	return -1;
}
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
			/* index = 0 on failure, which fails gracefully */
//			if (!index) return -1;
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
	void *real_socket_p = dlsym(RTLD_NEXT, "socket");
	if (!real_socket_p) abort();
	struct socket_enhancer_config *temp_config = calloc(sizeof(struct socket_enhancer_config), 1);
	if (!temp_config) abort();
	temp_config->real_bind = real_bind_p;
	temp_config->real_connect = real_connect_p;
	temp_config->real_socket = real_socket_p;
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
				case 0x62647072: /* "bdpr" */
					{
						struct bind_profile result = {};
						if (parse_bind_profile_string(value, &result)) {
							fprintf(stderr, "Invalid bind profile %s\n", value);
							abort();
						}
						size_t newidx = temp_config->bind_profile_size++;
						void *new_head = reallocarray(temp_config->bind_profile_head, sizeof(struct bind_profile), newidx+1);
						if (!new_head) {
							abort();
						}
						temp_config->bind_profile_head = new_head;
						memcpy(&temp_config->bind_profile_head[newidx], &result, sizeof(struct bind_profile));
						if (result.idx >= 16384) {
							temp_config->has_bp_high = 1;
						}
					}
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
		qsort(temp_config->bind_profile_head, temp_config->bind_profile_size, sizeof(struct bind_profile), compare_bind_profiles);
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
static int try_preconnect_bind_v4(int fd, const struct in_addr *bind_addr, int freebind, uint16_t bind_profile_idx, struct socket_enhancer_config *config) {
	struct sockaddr_in existing_address = {0};
	socklen_t addrlen = sizeof(struct sockaddr_in);
	if (getsockname(fd, (struct sockaddr *) &existing_address, &addrlen)) return -1;
	if (addrlen == sizeof(struct sockaddr_in)) {
		if (existing_address.sin_family == AF_INET) {
			if (*(uint32_t *) &existing_address.sin_addr) return 0;
			if (apply_bind_profile(fd, bind_profile_idx, 0, config, 0) < 0) return -1;
		}
	}
	if (!bind_addr) return 0;
	int one = 1;
	setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
	one = 1;
	if (freebind) setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one));
	memset(&existing_address, 0, sizeof(existing_address));
	existing_address.sin_family = AF_INET;
	memcpy(&existing_address.sin_addr, bind_addr, sizeof(struct in_addr));
	return config->real_bind(fd, (struct sockaddr *) &existing_address, sizeof(existing_address));
}
static int try_preconnect_bind_v6(int fd, const struct ipv6_with_scope *bind_addr, int freebind, uint16_t bind_profile_idx, struct socket_enhancer_config *config) {
	struct sockaddr_in6 existing_address = {0};
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	if (getsockname(fd, (struct sockaddr *) &existing_address, &addrlen)) return -1;
	if (addrlen == sizeof(struct sockaddr_in6)) {
		if (existing_address.sin6_family == AF_INET6) {
			if (existing_address.sin6_addr.s6_addr32[0]) return 0;
			if (existing_address.sin6_addr.s6_addr32[1]) return 0;
			if (existing_address.sin6_addr.s6_addr32[2]) return 0;
			if (existing_address.sin6_addr.s6_addr32[3]) return 0;
			if (apply_bind_profile(fd, bind_profile_idx, 0, config, 0) < 0) return -1;
		}
	}
	if (!bind_addr) return 0;
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
			int bind_profile_idx = 64;
			if (IN6_IS_ADDR_LINKLOCAL(&new_addr.ipv6_addr.sin6_addr)) {
				bind_profile_idx = 66;
				if (config->universal_link_local_mode & 2) {
					convert_universal_linklocal(&new_addr.ipv6_addr);
				}
				if (config->has_v6_linklocal) {
					bind_addr = &config->ipv6_linklocal;
					if (IN6_IS_ADDR_UNSPECIFIED(&bind_addr->address)) {
						if (!new_addr.ipv6_addr.sin6_scope_id) {
							new_addr.ipv6_addr.sin6_scope_id = bind_addr->scope_id;
						}
						bind_addr = NULL;
					}
				} else if (config->has_v6_default) {
					bind_addr = &config->ipv6_default;
				}
			} else if (IN6_IS_ADDR_V4MAPPED(&new_addr.ipv6_addr.sin6_addr)) {
				bind_profile_idx = 44;
				if (config->has_v6_v4mapv6) {
					bind_addr = &config->ipv6_v4mapv6;
				} else if (config->has_v4_default) {
					tmp_addr.address.s6_addr16[4] = 0;
					tmp_addr.address.s6_addr16[5] = 0xffff;
					tmp_addr.address.s6_addr32[3] = *(uint32_t *) &config->ipv4_default;
					bind_addr = &tmp_addr;
				}
			} else if ((new_addr.ipv6_addr.sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
				bind_profile_idx = 67;
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
			if (try_preconnect_bind_v6(fd, bind_addr, always_freebind, bind_profile_idx, config)) return -1;
		}
	} else if (len == sizeof(struct sockaddr_in)) {
		if (addr->sa_family == AF_INET) {
			memcpy(&new_addr.ipv4_addr, addr, sizeof(struct sockaddr_in));
			addr = (struct sockaddr *) &new_addr.ipv4_addr;
			struct in_addr *v4_address = &new_addr.ipv4_addr.sin_addr;
			if ((ntohl(v4_address->s_addr) & 0xff000000) == 0x7f000000) {
				if (try_preconnect_bind_v4(fd, config->has_v4_loopback ? &config->ipv4_loopback : NULL, always_freebind, 45, config)) return -1;
			} else {
				if (try_preconnect_bind_v4(fd, config->has_v4_default ? &config->ipv4_default : NULL, always_freebind, 44, config)) return -1;
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
	if (always_freebind) {
		int one = 1;
		setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one));
	}
	if (len == sizeof(struct sockaddr_in6)) {
		if (addr->sa_family == AF_INET6) {
			memcpy(&ipv6_addr, addr, sizeof(struct sockaddr_in6));
			addr = (struct sockaddr *) &ipv6_addr;
			if (config->universal_link_local_mode & 1) {
				convert_universal_linklocal(&ipv6_addr);
			}
			int r = apply_bind_profile_sockname(fd, (struct sockaddr *) &ipv6_addr, sizeof(struct sockaddr_in6), config, 1);
			if (r < 0) {
				if (errno == 0) errno = EADDRNOTAVAIL;
				return -1;
			}
			if (r == 1) return 0;
		}
	} else if ((len == sizeof(struct sockaddr_in)) && (addr->sa_family == AF_INET)) {
		struct sockaddr_in ipv4_addr;
		memcpy(&ipv4_addr, addr, sizeof(struct sockaddr_in));
		int r = apply_bind_profile_sockname(fd, (struct sockaddr *) &ipv4_addr, sizeof(struct sockaddr_in), config, 1);
		if (r < 0) {
			if (errno == 0) errno = EADDRNOTAVAIL;
			return -1;
		}
		if (r == 1) return 0;
	}
	return config->real_bind(fd, addr, len);
}
int socket(int domain, int type, int protocol) {
	struct socket_enhancer_config *config = __atomic_load_n(&global_config, __ATOMIC_SEQ_CST);
	if (!config) abort();
	int socket_return = config->real_socket(domain, type, protocol);
	if (socket_return < 0) return -1;
	switch (domain) {
		case AF_INET:
			if (apply_bind_profile(socket_return, 4, 0, config, 0) < 0) goto out;
			break;
		case AF_INET6:
			if (apply_bind_profile(socket_return, 6, 0, config, 0) < 0) goto out;
			break;
	}
	return socket_return;
out:
	close(socket_return);
	return -1;
}
