#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fat16.h"

char* FAT_FILE_NAME = "fat16.img";

/* 将扇区号为secnum的扇区读到buffer中 */
void sector_read(FILE* fd, unsigned int secnum, void* buffer)
{
    fseek(fd, BYTES_PER_SECTOR * secnum, SEEK_SET);
    fread(buffer, BYTES_PER_SECTOR, 1, fd);
}

/** TODO:
 * 将输入路径按“/”分割成多个字符串，并按照FAT文件名格式转换字符串
 * 
 * Hint1:假设pathInput为“/dir1/dir2/file.txt”，则将其分割成“dir1”，“dir2”，“file.txt”，
 *      每个字符串转换成长度为11的FAT格式的文件名，如“file.txt”转换成“FILE    TXT”，
 *      返回转换后的字符串数组，并将*pathDepth_ret设置为3
 * Hint2:可能会出现过长的字符串输入，如“/.Trash-1000”，需要自行截断字符串
**/
char** path_split(char* pathInput, int* pathDepth_ret)
{
    int    pathDepth;
    char** paths = malloc(pathDepth * sizeof(char*));
    char*  path  = malloc(11 * sizeof(char));
    int    i, j, k;
    char * p, *q;
    int    length = strlen(pathInput);
    for (p = strchr(pathInput, '/') + 1, q = strchr(p, '/'), pathDepth = 0;
         p - pathInput < length;
         p = q + 1, q = (strchr(p, '/') != NULL) ? strchr(p, '/') : pathInput + length, pathDepth++)
    {
        strncpy(path, p, q - p);
        *(path + (q - p))    = '\0';
        *(paths + pathDepth) = malloc(sizeof(char*));
        for (j = 0; j < 11; j++)
            *(*(paths + pathDepth) + j) = ' ';
        for (j = 0; path[j] != '\0'; j++)
        {
            if ((path[j]) == '.')
            {
                for (k = 0; k < 3; k++)
                {
                    if ((path[j + k + 1]) == '\0')
                        break;
                    else
                    {
                        *(*(paths + pathDepth) + 8 + k) = toupper(path[j + k + 1]);
                    }
                }
                break;
            }
            if (j < 8)
                *(*(paths + pathDepth) + j) = toupper(path[j]);
        }
    }
    *pathDepth_ret = pathDepth;
    return paths;
}

/** TODO:
 * 将FAT文件名格式解码成原始的文件名
 * 
 * Hint:假设path是“FILE    TXT”，则返回"file.txt"
**/
BYTE* path_decode(BYTE* path)
{
    BYTE* pathDecoded = malloc(MAX_SHORT_NAME_LEN * sizeof(BYTE));
    int   i, j;

    for (i = 0; i < 8; i++)
    {
        if (path[i] != ' ')
            pathDecoded[i] = tolower(path[i]);
        else
            break;
    }
    if (path[8] == ' ')
        pathDecoded[i] = '\0';
    else
    {
        pathDecoded[i++] = '.';
        for (j = 8; j < 11; j++, i++)
        {
            if (path[j] != ' ')
                pathDecoded[i] = tolower(path[j]);
            else
                break;
        }
    }
    return pathDecoded;
}

FAT16* pre_init_fat16(void)
{
    /* Opening the FAT16 image file */
    FILE*  fd;
    FAT16* fat16_ins;

    fd = fopen(FAT_FILE_NAME, "rb");

    if (fd == NULL)
    {
        fprintf(stderr, "Missing FAT16 image file!\n");
        exit(EXIT_FAILURE);
    }

    fat16_ins     = malloc(sizeof(FAT16));
    fat16_ins->fd = fd;
    /** TODO: 
   * 初始化fat16_ins的其余成员变量
   * Hint: root directory的大小与Bpb.BPB_RootEntCnt有关，并且是扇区对齐的
  **/
    fat16_ins->Bpb                = ;
    fat16_ins->FirstDataSector    = ;
    fat16_ins->FirstRootDirSecNum = ;
    return fat16_ins;
}

/** TODO:
 * 返回簇号为ClusterN对应的FAT表项
**/
WORD fat_entry_by_cluster(FAT16* fat16_ins, WORD ClusterN)
{
    BYTE sector_buffer[BYTES_PER_SECTOR];

    return 0xffff;
}

/**
 * 根据簇号ClusterN，获取其对应的第一个扇区的扇区号和数据，以及对应的FAT表项
**/
void first_sector_by_cluster(FAT16* fat16_ins, WORD ClusterN, WORD* FatClusEntryVal, WORD* FirstSectorofCluster, BYTE* buffer)
{
    *FatClusEntryVal      = fat_entry_by_cluster(fat16_ins, ClusterN);
    *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;

    sector_read(fat16_ins->fd, *FirstSectorofCluster, buffer);
}

/**
 * 从root directory开始，查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint: 假设path是“/dir1/dir2/file”，则先在root directory中查找名为dir1的目录，
 *       然后在dir1中查找名为dir2的目录，最后在dir2中查找名为file的文件，找到则返回0，并且将file的目录项数据写入到参数Dir对应的DIR_ENTRY中
**/
int find_root(FAT16* fat16_ins, DIR_ENTRY* Dir, const char* path)
{
    int    pathDepth;
    char** paths = path_split((char*)path, &pathDepth);

    /* 先读取root directory */
    int  i, j;
    int  RootDirCnt = 1; /* 用于统计已读取的扇区数 */
    BYTE buffer[BYTES_PER_SECTOR];

    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, buffer);

    /** TODO:
   * 查找名字为paths[0]的目录项，
   * 如果找到目录，则根据pathDepth判断是否需要调用find_subdir继续查找，
   * 
   * !!注意root directory可能包含多个扇区
  **/
    for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
    {

        /** 
     * return find_subdir(fat16_ins, Dir, paths, pathDepth, 1); 
    **/
    }

    return 1;
}

/** TODO:
 * 从子目录开始查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint1: 在find_subdir入口处，Dir应该是要查找的这一级目录的表项，需要根据其中的簇号，读取这级目录对应的扇区数据
 * Hint2: 目录的大小是未知的，可能跨越多个扇区或跨越多个簇；当查找到某表项以0x00开头就可以停止查找
 * Hint3: 需要查找名字为paths[curDepth]的文件或目录，同样需要根据pathDepth判断是否继续调用find_subdir函数
**/
int find_subdir(FAT16* fat16_ins, DIR_ENTRY* Dir, char** paths, int pathDepth, int curDepth)
{
    int  i, j;
    int  DirSecCnt = 1; /* 用于统计已读取的扇区数 */
    BYTE buffer[BYTES_PER_SECTOR];

    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

    return 1;
}

/**
 * ------------------------------------------------------------------------------
 * FUSE相关的函数实现
**/

void* fat16_init(struct fuse_conn_info* conn)
{
    struct fuse_context* context;
    context = fuse_get_context();

    return context->private_data;
}

void fat16_destroy(void* data)
{
    free(data);
}

int fat16_getattr(const char* path, struct stat* stbuf)
{
    FAT16* fat16_ins;

    struct fuse_context* context;
    context   = fuse_get_context();
    fat16_ins = (FAT16*)context->private_data;

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_dev     = fat16_ins->Bpb.BS_VollID;
    stbuf->st_blksize = BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus;
    stbuf->st_uid     = getuid();
    stbuf->st_gid     = getgid();

    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode   = S_IFDIR | S_IRWXU;
        stbuf->st_size   = 0;
        stbuf->st_blocks = 0;
        stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = 0;
    }
    else
    {
        DIR_ENTRY Dir;

        int res = find_root(fat16_ins, &Dir, path);

        if (res == 0)
        {
            if (Dir.DIR_Attr == ATTR_DIRECTORY)
            {
                stbuf->st_mode = S_IFDIR | 0755;
            }
            else
            {
                stbuf->st_mode = S_IFREG | 0755;
            }
            stbuf->st_size = Dir.DIR_FileSize;

            if (stbuf->st_size % stbuf->st_blksize != 0)
            {
                stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize) + 1;
            }
            else
            {
                stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize);
            }

            struct tm t;
            memset((char*)&t, 0, sizeof(struct tm));
            t.tm_sec        = Dir.DIR_WrtTime & ((1 << 5) - 1);
            t.tm_min        = (Dir.DIR_WrtTime >> 5) & ((1 << 6) - 1);
            t.tm_hour       = Dir.DIR_WrtTime >> 11;
            t.tm_mday       = (Dir.DIR_WrtDate & ((1 << 5) - 1));
            t.tm_mon        = (Dir.DIR_WrtDate >> 5) & ((1 << 4) - 1);
            t.tm_year       = 80 + (Dir.DIR_WrtDate >> 9);
            stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = mktime(&t);
        }
    }
    return 0;
}

int fat16_readdir(const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
    FAT16* fat16_ins;
    BYTE   sector_buffer[BYTES_PER_SECTOR];
    int    i;
    int    RootDirCnt = 1, DirSecCnt = 1; /* 用于统计已读取的扇区数 */

    struct fuse_context* context;
    context   = fuse_get_context();
    fat16_ins = (FAT16*)context->private_data;

    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);

    if (strcmp(path, "/") == 0)
    {
        DIR_ENTRY Root;

        /** TODO:
     * 将root directory下的文件或目录通过filler填充到buffer中
     * 注意不需要遍历子目录
    **/

        for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
        {

            /**
       * const char *filename = (const char *)path_decode(Root.DIR_Name);
       * filler(buffer, filename, NULL, 0);
      **/
        }
    }
    else
    {
        DIR_ENTRY Dir;

        /** TODO:
     * 通过find_root获取path对应的目录的目录项，
     * 然后访问该目录，将其下的文件或目录通过filler填充到buffer中，
     * 同样注意不需要遍历子目录
     * Hint: 需要考虑目录大小，可能跨扇区，跨簇
    **/
        find_root(fat16_ins, &Dir, path);

        WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
    }

    return 0;
}

/** TODO:
 * 从path对应的文件的offset字节处开始读取size字节的数据到buffer中，并返回实际读取的字节数
 * 
 * Hint: 文件大小属性是Dir.DIR_FileSize；当offset超过文件大小时，应该返回0
**/
int fat16_read(const char* path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi)
{
    FAT16*               fat16_ins;
    struct fuse_context* context;
    context   = fuse_get_context();
    fat16_ins = (FAT16*)context->private_data;

    return 0;
}

/**
 * ------------------------------------------------------------------------------
 * 测试函数
**/

void test_path_split()
{
    printf("#1 running %s\n", __FUNCTION__);

    char s[][32]     = {"/texts", "/dir1/dir2/file.txt", "/.Trash-100"};
    int  dr[]        = {1, 3, 1};
    char sr[][3][32] = {{"TEXTS      "}, {"DIR1       ", "DIR2       ", "FILE    TXT"}, {"        TRA"}};

    int i, j, r;
    for (i = 0; i < sizeof(dr) / sizeof(dr[0]); i++)
    {

        char** ss = path_split(s[i], &r);
        assert(r == dr[i]);
        for (j = 0; j < dr[i]; j++)
        {
            assert(strcmp(sr[i][j], ss[j]) == 0);
            free(ss[j]);
        }
        free(ss);
        printf("test case %d: OK\n", i + 1);
    }

    printf("success in %s\n\n", __FUNCTION__);
}

void test_path_decode()
{
    printf("#2 running %s\n", __FUNCTION__);

    char s[][32]  = {"..         ", "FILE    TXT", "ABCD    RM "};
    char sr[][32] = {"..", "file.txt", "abcd.rm"};

    int i, j, r;
    for (i = 0; i < sizeof(s) / sizeof(s[0]); i++)
    {
        char* ss = (char*)path_decode(s[i]);
        assert(strcmp(ss, sr[i]) == 0);
        free(ss);
        printf("test case %d: OK\n", i + 1);
    }

    printf("success in %s\n\n", __FUNCTION__);
}

void test_pre_init_fat16()
{
    printf("#3 running %s\n", __FUNCTION__);

    FAT16* fat16_ins = pre_init_fat16();

    assert(fat16_ins->FirstRootDirSecNum == 124);
    assert(fat16_ins->FirstDataSector == 156);
    assert(fat16_ins->Bpb.BPB_RsvdSecCnt == 4);
    assert(fat16_ins->Bpb.BPB_RootEntCnt == 512);
    assert(fat16_ins->Bpb.BS_BootSig == 41);
    assert(fat16_ins->Bpb.BS_VollID == 1576933109);
    assert(fat16_ins->Bpb.Signature_word == 43605);

    fclose(fat16_ins->fd);
    free(fat16_ins);

    printf("success in %s\n\n", __FUNCTION__);
}

void test_fat_entry_by_cluster()
{
    printf("#4 running %s\n", __FUNCTION__);

    FAT16* fat16_ins = pre_init_fat16();

    int cn[] = {1, 2, 4};
    int ce[] = {65535, 0, 65535};

    int i;
    for (i = 0; i < sizeof(cn) / sizeof(cn[0]); i++)
    {
        int r = fat_entry_by_cluster(fat16_ins, cn[i]);
        assert(r == ce[i]);
        printf("test case %d: OK\n", i + 1);
    }

    fclose(fat16_ins->fd);
    free(fat16_ins);

    printf("success in %s\n\n", __FUNCTION__);
}

void test_find_root()
{
    printf("#5 running %s\n", __FUNCTION__);

    FAT16* fat16_ins = pre_init_fat16();

    char path[][32]  = {"/dir1", "/makefile", "/log.c"};
    char names[][32] = {"DIR1       ", "MAKEFILE   ", "LOG     C  "};
    int  others[][3] = {{100, 4, 0}, {100, 8, 226}, {100, 3, 517}};

    int i;
    for (i = 0; i < sizeof(path) / sizeof(path[0]); i++)
    {
        DIR_ENTRY Dir;
        find_root(fat16_ins, &Dir, path[i]);
        assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
        assert(Dir.DIR_CrtTimeTenth == others[i][0]);
        assert(Dir.DIR_FstClusLO == others[i][1]);
        assert(Dir.DIR_FileSize == others[i][2]);

        printf("test case %d: OK\n", i + 1);
    }

    fclose(fat16_ins->fd);
    free(fat16_ins);

    printf("success in %s\n\n", __FUNCTION__);
}

void test_find_subdir()
{
    printf("#6 running %s\n", __FUNCTION__);

    FAT16* fat16_ins = pre_init_fat16();

    char path[][32]  = {"/dir1/dir2", "/dir1/dir2/dir3", "/dir1/dir2/dir3/test.c"};
    char names[][32] = {"DIR2       ", "DIR3       ", "TEST    C  "};
    int  others[][3] = {{100, 5, 0}, {0, 6, 0}, {0, 7, 517}};

    int i;
    for (i = 0; i < sizeof(path) / sizeof(path[0]); i++)
    {
        DIR_ENTRY Dir;
        find_root(fat16_ins, &Dir, path[i]);
        assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
        assert(Dir.DIR_CrtTimeTenth == others[i][0]);
        assert(Dir.DIR_FstClusLO == others[i][1]);
        assert(Dir.DIR_FileSize == others[i][2]);

        printf("test case %d: OK\n", i + 1);
    }

    fclose(fat16_ins->fd);
    free(fat16_ins);

    printf("success in %s\n\n", __FUNCTION__);
}

struct fuse_operations fat16_oper = {
    .init    = fat16_init,
    .destroy = fat16_destroy,
    .getattr = fat16_getattr,
    .readdir = fat16_readdir,
    .read    = fat16_read};

int main(int argc, char* argv[])
{
    int ret;

    if (strcmp(argv[1], "--test") == 0)
    {
        printf("--------------\nrunning test\n--------------\n");
        FAT_FILE_NAME = "fat16_test.img";
        test_path_split();
        test_path_decode();
        test_pre_init_fat16();
        test_fat_entry_by_cluster();
        test_find_root();
        test_find_subdir();
        exit(EXIT_SUCCESS);
    }

    FAT16* fat16_ins = pre_init_fat16();

    ret = fuse_main(argc, argv, &fat16_oper, fat16_ins);

    return ret;
}