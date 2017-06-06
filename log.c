
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static char *BufferLog, *WriteHead, *BufferEnd;
static int WriteWrapped;

int log_str(char *str) {
    size_t size_to_end;
    size_t log_size;

    size_to_end = BufferEnd - WriteHead;

    log_size = snprintf(WriteHead, size_to_end+1, "%s\n", str);

    if (log_size > size_to_end) {
        if (log_size > 500) {
            /* truncate this line */
            memcpy(BufferLog, "*****\n", 6);
            WriteHead = BufferLog + 6;
        } else {
            char tmp[512];
            int left = log_size - size_to_end;
            assert(snprintf(tmp, sizeof(tmp), "%s\n", str) < sizeof(tmp));
            memcpy(BufferLog, tmp + log_size - left, left);
            WriteHead = BufferLog + left;
        }

        WriteWrapped = 1;
    } else {
        WriteHead += log_size;
        assert(WriteHead <= BufferEnd);
        if (WriteHead == BufferEnd) {
            WriteWrapped = 1;
            WriteHead = BufferLog;
        }
    }


    return 0;
}

int log_print(int fd) {
    int size;
    char *start;

    if (!WriteWrapped) {
        start = BufferLog;
        size = WriteHead - BufferLog;
    } else {
        start = strchr(WriteHead+1, '\n');
        if (start) {
            size = BufferEnd - BufferLog - (start - WriteHead);
        } else {
            start = strchr(BufferLog, '\n');
            if (!start) return 0;
            size = WriteHead - start;
        }
    }

    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size));

    if (start < WriteHead) {
        write(fd, start, size);
    } else {
        write(fd, start, BufferEnd - start);
        write(fd, BufferLog, WriteHead - BufferLog);
    }

    return 0;
}

int log_init(int buffer_size) {
    assert(buffer_size > 512);
    assert(BufferLog = malloc(buffer_size+1));
    WriteHead = BufferLog;
    BufferEnd = BufferLog + buffer_size;
    WriteWrapped = 0;

    return 0;
}
