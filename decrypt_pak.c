#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decrypt_central_dir(unsigned long pt, char *buf, unsigned long size) {
    printf("decrypt_central_dir init pt: %lu\n", pt);
    while (1) {
        if (pt >= size) {
            printf("end\n");
            break;
        }

        if (*((unsigned int*)(buf + pt)) != 0xf00d8bad) {
            printf("sig err\n");
            break;
        } else {
            *(unsigned int*)(buf + pt) = 0x02014b50;
        }

        unsigned long version_made = pt + 0x4;
        unsigned long version_need = pt + 0x6;
        unsigned long general_purpose_big_flag = pt + 0x8;
        unsigned long compression_method = pt + 0xa;
        unsigned long last_modify_time = pt + 0xc;
        unsigned long last_modify_date = pt + 0xe;
        unsigned long crc = pt + 0x10;
        unsigned long compressed_size = pt + 0x14;
        unsigned long uncompressed_size = pt + 0x18;
        unsigned long file_name_length = pt + 0x1c;
        unsigned long extra_field_length = pt + 0x1e;
        unsigned long comment_length = pt + 0x20;
        unsigned long disk_num_start = pt + 0x22;
        unsigned long internal_attr = pt + 0x24;
        unsigned long external_attr = pt + 0x26;
        unsigned long relative_offset = pt + 0x2a;

        *(unsigned short*)(buf + version_made) = *(unsigned short*)(buf + version_made) ^ 0xc242;
        *(unsigned short*)(buf + version_need) = *(unsigned short*)(buf + version_need) ^ 0xc242;
        *(unsigned short*)(buf + general_purpose_big_flag) = *(unsigned short*)(buf + general_purpose_big_flag) ^ 0xc242;
        *(unsigned short*)(buf + compression_method) = *(unsigned short*)(buf + compression_method) ^ 0xc242;
        *(unsigned short*)(buf + last_modify_time) = *(unsigned short*)(buf + last_modify_time) ^ 0xc242;
        *(unsigned short*)(buf + last_modify_date) = *(unsigned short*)(buf + last_modify_date) ^ 0xc242;
        *(unsigned int*)(buf + crc) = *(unsigned int*)(buf + crc) ^ 0x1174750;
        *(unsigned int*)(buf + compressed_size) = *(unsigned int*)(buf + compressed_size) ^ 0x1174750;
        *(unsigned int*)(buf + uncompressed_size) = *(unsigned int*)(buf + uncompressed_size) ^ 0x1174750;
        *(unsigned short*)(buf + file_name_length)= *(unsigned short*)(buf + file_name_length) ^ 0xc242;
        *(unsigned short*)(buf + extra_field_length) = *(unsigned short*)(buf + extra_field_length) ^ 0xc242;
        *(unsigned short*)(buf + comment_length) = *(unsigned short*)(buf + comment_length) ^ 0xc242;
        *(unsigned short*)(buf + disk_num_start) = *(unsigned short*)(buf + disk_num_start) ^ 0xc242;
        *(unsigned short*)(buf + internal_attr) = *(unsigned short*)(buf + internal_attr) ^ 0xc242;
        *(unsigned int*)(buf + external_attr) = *(unsigned int*)(buf + external_attr) ^ 0x1174750;
        *(unsigned int*)(buf + relative_offset) = *(unsigned int*)(buf + relative_offset) ^ 0x1174750;


        unsigned short name_length = *(unsigned short*)(buf + file_name_length);
        printf("file name length: %d\n", name_length);
        unsigned long index = pt + 0x2e;
        int i = 0;
        for (; i < name_length; i++) {
            buf[index+i] = (unsigned char)(buf[index+i] ^ 0xcd);
        }

        unsigned short extra_field_length_s = *(unsigned short*)(buf + extra_field_length);
        printf("extra field length: %d\n", extra_field_length_s);
        index += name_length;
        i = 0;
        for (; i < extra_field_length_s; i++) {
            buf[index+i] = (unsigned char)(buf[index+i] ^ 0xcd);
        }

        unsigned short file_comment_length = *(unsigned short*)(buf + comment_length);
        printf("file comment length: %d\n", file_comment_length);
        index += extra_field_length_s;
        i = 0;
        for (; i < file_comment_length; i++) {
            buf[index+i] = (unsigned char)(buf[index+i] ^ 0xcd);
        }

        pt = index + file_comment_length;
    }
}

void decrypt_head(char *buf, unsigned long size) {
    unsigned long pt = 0;
    printf("decrypt_head init pt: %lu\n", pt);
    while (1){
        if (pt >= size) {
            printf("end\n");
            break;
        }

        if (*((unsigned int*)(buf + pt)) != 0x8badf00d) {
            if (*((unsigned int*)(buf + pt)) == 0xf00d8bad) {
                decrypt_central_dir(pt, buf, size);
            } {
                printf("sig err\n");
            }
            break;
        } else {
            *(unsigned int*)(buf + pt) = 0x04034b50;
        }
        unsigned long file_name_length = pt + 0x1a;
        unsigned long extra_field_length = pt + 0x1c;
        unsigned long version = pt + 0x4;
        unsigned long general_purpose_big_flag = pt + 0x6;
        unsigned long compression_method = pt + 0x8;
        unsigned long last_modify_time = pt + 0xa;
        unsigned long last_modify_date = pt + 0xc;
        unsigned long crc = pt + 0xe;
        unsigned long compressed_size = pt + 0x12;
        unsigned long uncompressed_size = pt + 0x16;

        *(unsigned short*)(buf + file_name_length)= *(unsigned short*)(buf + file_name_length) ^ 0xc242;
        *(unsigned short*)(buf + version) = *(unsigned short*)(buf + version) ^ 0xc242;
        *(unsigned short*)(buf + general_purpose_big_flag) = *(unsigned short*)(buf + general_purpose_big_flag) ^ 0xc242;
        *(unsigned short*)(buf + compression_method) = *(unsigned short*)(buf + compression_method) ^ 0xc242;
        *(unsigned short*)(buf + extra_field_length) = *(unsigned short*)(buf + extra_field_length) ^ 0xc242;
        *(unsigned short*)(buf + last_modify_time) = *(unsigned short*)(buf + last_modify_time) ^ 0xc242;
        *(unsigned short*)(buf + last_modify_date) = *(unsigned short*)(buf + last_modify_date) ^ 0xc242;
        *(unsigned int*)(buf + crc) = *(unsigned int*)(buf + crc) ^ 0x1174750;
        *(unsigned int*)(buf + compressed_size) = *(unsigned int*)(buf + compressed_size) ^ 0x1174750;
        *(unsigned int*)(buf + uncompressed_size) = *(unsigned int*)(buf + uncompressed_size) ^ 0x1174750;

        unsigned short name_length = *(unsigned short*)(buf + file_name_length);
        printf("file name length: %d\n", name_length);
        unsigned long index = pt + 0x1e;
        int i = 0;
        for (; i < name_length; i++) {
            buf[index+i] = (unsigned char)(buf[index+i] ^ 0xcd);
        }

        pt += name_length + 0x1e + *(unsigned int*)(buf + compressed_size);
        printf("pt: %lu\n", pt);
    }
}


void dump_file(char* file_name, char* buf, unsigned long size) {
    char *write_file_name = malloc(strlen(file_name) + strlen(".zip") + 1);
    strcpy(write_file_name, file_name);
    strcat(write_file_name, ".zip");
    FILE *fp = fopen(write_file_name, "wb");
    fwrite(buf, 1, size, fp);
    fclose(fp);
}

int main(int argc, const char *argv[])
{
    char *file_name = argv[1];
    //char *file_name = "/Users/bingmini/Desktop/config.pak";
    FILE *fp = fopen(file_name, "rb");

    unsigned char *pBuffer = NULL;
    unsigned long size = 0;
    fseek(fp,0,SEEK_END);
    size = ftell(fp);
    fseek(fp,0,SEEK_SET);
    pBuffer = (unsigned char*)malloc(size);
    printf("file buffer got\n");
    size = fread(pBuffer,sizeof(unsigned char), size, fp);
    fclose(fp);

    decrypt_head(pBuffer, size);

    dump_file(file_name, pBuffer, size);

    return 0;
}
