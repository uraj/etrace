#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct eevent_t
{
    uint16_t len;
    uint16_t syscall_no;
    int16_t  id;
    uint16_t reserved;
    struct
    {
        uint32_t sec;
        uint32_t nanosec;
    } etime;
    char params[0];
} __attribute__((packed));

#define EEVENT_READ_NO   2
#define EEVENT_WRITE_NO  3
#define EEVENT_TOTAL     4

static char *syscall_name[EEVENT_TOTAL] =
{
    [EEVENT_READ_NO] = "read",
    [EEVENT_WRITE_NO] = "write",
};

int parse(FILE *);
void print_entry(struct eevent_t *);

int main(int argc, char *argv[])
{
    char *filename;
    FILE *datafile;
    int entry_count;
    
    if (argc == 1)
        filename = "elog.dat";
    else
        filename = argv[1];

    datafile = fopen(filename, "rb");
    if(datafile == NULL)
    {
        fprintf(stderr, "File not exist\n");
        return 1;
    }

    entry_count = parse(datafile);
    
    fclose(datafile);

    printf("Parsed %d elog etries.\n", entry_count);
    
    return 0;
}

int parse(FILE *datafile)
{
    uint8_t *buf;
    struct eevent_t *eevent;
    int bufsize = sizeof(struct eevent_t) << 2;
    long int filesize, count = 0;
    int entries = 0;
    
    fseek(datafile, 0, SEEK_END);
    filesize = ftell(datafile);
    fseek(datafile, 0, SEEK_SET);
    
    eevent = (struct eevent_t *)malloc(bufsize);

    while (count < filesize)
    {
        fread(eevent, sizeof(struct eevent_t), 1, datafile);
        if (eevent->len + sizeof(struct eevent_t) > bufsize)
        {
            bufsize <<= 1;
            eevent = realloc(eevent, bufsize);
        }
        fread(eevent->params, 1, eevent->len, datafile);
        print_entry(eevent);
        count += eevent->len + sizeof(struct eevent_t);
        ++entries;
    }
    
    free(eevent);
    
    return entries;
}

void print_entry(struct eevent_t *eevent)
{
    static char *suffix[] = { "(ent)", "(ret)", };
    int16_t suffix_select;
    int16_t id;

    if (eevent->id < 0)
    {
        id = -eevent->id;
        suffix_select = 1;
    }
    else
    {
        id = eevent->id;
        suffix_select = 0;
    }
    
    printf("%s%s:\t%hd\t%u.%u\t%.*s\n",
           syscall_name[eevent->syscall_no],
           suffix[suffix_select],
           id,
           eevent->etime.sec,
           eevent->etime.nanosec / 1000000,
           eevent->len,
           eevent->params);

    return;
}
