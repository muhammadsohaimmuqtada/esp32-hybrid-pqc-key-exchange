#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void randombytes(uint8_t *out, size_t outlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, out, outlen);
        close(fd);
    }
}
