#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// Function to retrieve the default gateway address
int get_gateway(struct in_addr *gw_addr) {
    FILE *fp;
    char line[256];

    fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("Failed to open /proc/net/route");
        return -1;
    }

    // Skip the first line (header)
    if (!fgets(line, sizeof(line), fp)) {
        perror("Failed to read from /proc/net/route");
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char iface[16];
        unsigned long destination, gateway;

        // Parse the line for interface, destination, and gateway
        if (sscanf(line, "%15s %lx %lx", iface, &destination, &gateway) == 3) {
            // Check for default route (destination is 0.0.0.0)
            if (destination == 0) {
                gw_addr->s_addr = htonl(gateway);  // Correct byte order
                fclose(fp);
                return 0;
            }
        }
    }

    fprintf(stderr, "Default gateway not found\n");
    fclose(fp);
    return -1;
}

// Function to print detailed information about a network device
void print_device_info(pcap_if_t *device, struct in_addr gw_addr) {
    int has_valid_ip = 0;

    for (pcap_addr_t *a = device->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET) { // IPv4 only
            struct sockaddr_in *sockaddr = (struct sockaddr_in *)a->addr;
            char ip[INET_ADDRSTRLEN];
            char netmask[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(sockaddr->sin_addr), ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(((struct sockaddr_in *)a->netmask)->sin_addr), netmask, INET_ADDRSTRLEN);

            printf("Device: %s\n", device->name);
            printf("IP Address: %s\n", ip);
            printf("Netmask: %s\n", netmask);
            if (a->broadaddr != NULL) {
                printf("Broadcast Address: %s\n", inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
            } else {
                printf("Broadcast Address: Not available\n");
            }
            printf("Gateway: %s\n", inet_ntoa(gw_addr));
            printf("=====================================\n");

            has_valid_ip = 1;
        }
    }

    if (!has_valid_ip) {
        printf("Device: %s\nNo valid IPv4 addresses found\n=====================================\n", device->name);
    }
}

int is_relevant_device(const char *device_name) {
    // Skip irrelevant or virtual devices
    const char *irrelevant_devices[] = {"any", "nflog", "nfqueue", "bluetooth-monitor", "dbus-system", "dbus-session"};
    for (size_t i = 0; i < sizeof(irrelevant_devices) / sizeof(irrelevant_devices[0]); ++i) {
        if (strcmp(device_name, irrelevant_devices[i]) == 0) {
            return 0;
        }
    }
    return 1; // Relevant device
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // Retrieve the list of network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Get the default gateway address
    struct in_addr gw_addr;
    if (get_gateway(&gw_addr) == -1) {
        fprintf(stderr, "Error retrieving default gateway address\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Print device information
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (is_relevant_device(d->name)) {
            print_device_info(d, gw_addr);
        }
    }

    // Free the device list
    pcap_freealldevs(alldevs);

    return 0;
}
