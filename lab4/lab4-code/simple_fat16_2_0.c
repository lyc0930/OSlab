#include <assert.h>
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
    int    pathDepth = 1;
    char** paths     = malloc(pathDepth * sizeof(char*));
    paths[0]         = malloc(11 * sizeof(char));
    int i, j;
    int pathLen = strlen(pathInput);

    j = 0;
    for (i = 0; i < pathLen; i++)
    {
        if (pathInput[i] == '/')
        {
            if (i == 0)
                continue;
            else
            {
                while (j < 11) //用空格把剩下的填充满
                    paths[pathDepth - 1][j++] = ' ';
                pathDepth++;
                paths                = realloc(paths, pathDepth * sizeof(char*));
                paths[pathDepth - 1] = malloc(11 * sizeof(char));
                j                    = 0;
            }
        }
        else if (pathInput[i] == '.')
        {
            while (j < 8)
                paths[pathDepth - 1][j++] = ' ';
        }
        else
        {
            if (j == 11)
                continue;
            else
            {
                if (pathInput[i] >= 97 && pathInput[i] <= 122) //小写字母转换为大写字母
                    paths[pathDepth - 1][j++] = pathInput[i] - 32;
                else
                    paths[pathDepth - 1][j++] = pathInput[i];
            }
        }
    }
    while (j < 11) //用空格把剩下的填充满
        paths[pathDepth - 1][j++] = ' ';

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
    int   doteAdded      = 0;
    BYTE  CUR_DIR[12]    = ".          ";
    BYTE  PARENT_DIR[12] = "..         ";

    if (strncmp("   ", path + 8, 3) == 0) //后面三个字符都是空格
    {
        doteAdded = 1; //加过点，相当于不要加点
    }

    //两个特殊的文件名特殊处理
    if (strcmp(path, CUR_DIR) == 0)
    {
        pathDecoded[0] = '.';
        pathDecoded[1] = '\0';
    }

    else if (strcmp(path, PARENT_DIR) == 0)
    {
        pathDecoded[0] = '.';
        pathDecoded[1] = '.';
        pathDecoded[2] = '\0';
    }

    else
    {
        for (i = 0, j = 0; i < 11; i++)
        {
            if (path[i] == 0x00)
            {
                return "";
            }
            else if (path[i] == ' ' && doteAdded == 0)
            {
                pathDecoded[j++] = '.';
                doteAdded        = 1;
                i                = 7;
            }
            else if (path[i] == ' ' && i >= 0)
            {
                continue;
            }
            else if (i == 8 && doteAdded == 0)
            {
                pathDecoded[j++] = '.';
                doteAdded        = 1;
                i--;
            }
            else if (path[i] >= 65 && path[i] <= 90)
                pathDecoded[j++] = path[i] + 32;
            else
                pathDecoded[j++] = path[i];
        }
        pathDecoded[j] = '\0'; //字符串结尾符加上
    }

    return pathDecoded;
}

FAT16* pre_init_fat16(void)
{
    /* Opening the FAT16 image file */
    FILE*  fd;
    FAT16* fat16_ins;
    BYTE   DBR_buffer[BYTES_PER_SECTOR];

    fd = fopen(FAT_FILE_NAME, "rb");

    if (fd == NULL)
    {
        fprintf(stderr, "Missing FAT16 image file!\n");
        exit(EXIT_FAILURE);
    }

    fat16_ins = malloc(sizeof(FAT16));
    memset(fat16_ins, 0x00, sizeof(FAT16));

    fat16_ins->fd = fd;
    sector_read(fd, 0, DBR_buffer); //读取DBR扇区的数据

    /** TODO: 
   * 初始化fat16_ins的其余成员变量
   * Hint: root directory的大小与Bpb.BPB_RootEntCnt有关，并且是扇区对齐的
  **/

    //通过读取DBR扇区赋值
    memcpy(fat16_ins->Bpb.BS_jmpBoot, DBR_buffer, 3);
    memcpy(fat16_ins->Bpb.BS_OEMName, DBR_buffer + 0x03, 8);
    memcpy(&fat16_ins->Bpb.BPB_BytsPerSec, DBR_buffer + 0x0b, 2);
    memcpy(&fat16_ins->Bpb.BPB_SecPerClus, DBR_buffer + 0x0d, 1);
    memcpy(&fat16_ins->Bpb.BPB_RsvdSecCnt, DBR_buffer + 0x0e, 2);
    memcpy(&fat16_ins->Bpb.BPB_NumFATS, DBR_buffer + 0x10, 1);
    memcpy(&fat16_ins->Bpb.BPB_RootEntCnt, DBR_buffer + 0x11, 2);
    memcpy(&fat16_ins->Bpb.BPB_TotSec16, DBR_buffer + 0x13, 2);
    memcpy(&fat16_ins->Bpb.BPB_Media, DBR_buffer + 0x15, 1);
    memcpy(&fat16_ins->Bpb.BPB_FATSz16, DBR_buffer + 0x16, 2);
    memcpy(&fat16_ins->Bpb.BPB_SecPerTrk, DBR_buffer + 0x18, 2);
    memcpy(&fat16_ins->Bpb.BPB_NumHeads, DBR_buffer + 0x1a, 2);
    memcpy(&fat16_ins->Bpb.BPB_HiddSec, DBR_buffer + 0x1c, 4);
    memcpy(&fat16_ins->Bpb.BPB_TotSec32, DBR_buffer + 0x20, 4);
    memcpy(&fat16_ins->Bpb.BS_DrvNum, DBR_buffer + 0x24, 1);
    memcpy(&fat16_ins->Bpb.BS_Reserved1, DBR_buffer + 0x25, 1);
    memcpy(&fat16_ins->Bpb.BS_BootSig, DBR_buffer + 0x26, 1);
    memcpy(&fat16_ins->Bpb.BS_VollID, DBR_buffer + 0x27, 4);
    memcpy(fat16_ins->Bpb.BS_VollLab, DBR_buffer + 0x2b, 11);
    memcpy(fat16_ins->Bpb.BS_FilSysType, DBR_buffer + 0x36, 8);
    memcpy(fat16_ins->Bpb.Reserved2, DBR_buffer + 0x3e, 448);
    memcpy(&fat16_ins->Bpb.Signature_word, DBR_buffer + 0x01fe, 2);
    fat16_ins->FirstRootDirSecNum = fat16_ins->Bpb.BPB_RsvdSecCnt +
                                    fat16_ins->Bpb.BPB_NumFATS * fat16_ins->Bpb.BPB_FATSz16;
    fat16_ins->FirstDataSector = fat16_ins->FirstRootDirSecNum + 32;

    return fat16_ins;
}

/** TODO:
 * 返回簇号为ClusterN对应的FAT表项
**/
WORD fat_entry_by_cluster(FAT16* fat16_ins, WORD ClusterN)
{
    BYTE FAT_sector_buffer[BYTES_PER_SECTOR];
    WORD FAT_ClusterN   = ClusterN * 2;
    WORD FAT_sector_num = FAT_ClusterN / BYTES_PER_SECTOR + fat16_ins->Bpb.BPB_RsvdSecCnt;
    WORD FAT_Entry;

    sector_read(fat16_ins->fd, FAT_sector_num, FAT_sector_buffer);
    // a bug that costs two days: '%' is forgeten !!!
    FAT_Entry = FAT_sector_buffer[FAT_ClusterN % BYTES_PER_SECTOR] + FAT_sector_buffer[(FAT_ClusterN + 1) % BYTES_PER_SECTOR] * 0x0100;

    return FAT_Entry;
}

/**
 * 根据簇号ClusterN，获取其对应的第一个扇区的扇区号和数据，以及对应的FAT表项
**/
void first_sector_by_cluster(FAT16* fat16_ins, WORD ClusterN, WORD* FatClusEntryVal, WORD* FirstSectorofCluster, BYTE* buffer)
{
    *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;
    *FatClusEntryVal      = fat_entry_by_cluster(fat16_ins, ClusterN);

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
    int i;
    int RootDirCnt = 1; /* 用于统计已读取的扇区数 */
    //一个扇区容纳16个32 bytes的目录项
    BYTE buffer[BYTES_PER_SECTOR];

    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, buffer);

    /** TODO:
   * 查找名字为paths[0]的目录项，
   * 如果找到目录，则根据pathDepth判断是否需要调用find_subdir继续查找，
   * 
   * !!注意root directory可能包含多个扇区
  **/
    for (i = 0; i < fat16_ins->Bpb.BPB_RootEntCnt; i++)
    {
        // 一个扇区的16个目录项读完，需要更换为下一个扇区
        if (i % 16 == 0 && i != 0)
        {
            RootDirCnt++;
            sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt - 1, buffer);
        }

        if (strncmp(paths[0], buffer + i % 16 * BYTES_PER_DIR, 11) == 0)
        {
            memcpy(Dir, buffer + i % 16 * BYTES_PER_DIR, BYTES_PER_DIR);

            if (pathDepth == 1)
                return 0;
            else
                return find_subdir(fat16_ins, Dir, paths, pathDepth, 1);
        }
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
    int  i;
    int  DirSecCnt = 1; /* 用于统计已读取的扇区数 */
    BYTE buffer[BYTES_PER_SECTOR];
    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

    ClusterN = Dir->DIR_FstClusLO;
    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);

    i = 0;
    while (1)
    {
        // 一个扇区的16个目录项读完，需要更换为下一个扇区，同时更新FAT表项
        if (i % 16 == 0 && i != 0)
        {
            DirSecCnt++;
            sector_read(fat16_ins->fd, FirstSectorofCluster + (DirSecCnt - 1) % 4, buffer);
        }

        if (i % (16 * fat16_ins->Bpb.BPB_SecPerClus) == 0 && i != 0)
        {
            DirSecCnt = 1;
            first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, buffer);
        }

        if (FatClusEntryVal == 0x00)
            break;

        if (strncmp(paths[curDepth], buffer + i % 16 * BYTES_PER_DIR, 11) == 0)
        {
            memcpy(Dir, buffer + i % 16 * BYTES_PER_DIR, BYTES_PER_DIR);

            if (pathDepth == curDepth + 1)
                return 0;
            else
                return find_subdir(fat16_ins, Dir, paths, pathDepth, curDepth + 1);
        }

        i++;
    }

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
    FAT16*      fat16_ins;
    BYTE        sector_buffer[BYTES_PER_SECTOR];
    int         i;
    int         RootDirCnt = 1, DirSecCnt = 1; /* 用于统计已读取的扇区数 */
    const char* filename;

    struct fuse_context* context;
    context   = fuse_get_context();
    fat16_ins = (FAT16*)context->private_data;

    if (strcmp(path, "/") == 0)
    {
        DIR_ENTRY Root;

        /** TODO:
     * 将root directory下的文件或目录通过filler填充到buffer中
     * 注意不需要遍历子目录
    **/
        sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);

        filler(buffer, ".", NULL, 0);
        filler(buffer, "..", NULL, 0);
        for (i = 0; i < fat16_ins->Bpb.BPB_RootEntCnt; i++)
        {
            // 一个扇区的16个目录项读完，需要更换为下一个扇区
            if (i % 16 == 0 && i != 0)
            {
                RootDirCnt++;
                sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt - 1, sector_buffer);
            }

            memcpy(&Root, sector_buffer + i % 16 * BYTES_PER_DIR, BYTES_PER_DIR);

            filename = (const char*)path_decode(Root.DIR_Name);
            if (strcmp(filename, "") != 0)
                filler(buffer, filename, NULL, 0);
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

        ClusterN = Dir.DIR_FstClusLO;
        first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);

        i = 0;
        while (1)
        {
            // 一个扇区的16个目录项读完，需要更换为下一个扇区
            // 一个簇读完，切换到下一个簇的第一个扇区，同时更新FAT表项
            if (i % (16 * fat16_ins->Bpb.BPB_SecPerClus) == 0 && i != 0)
            {
                DirSecCnt = 1;
                first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
            }
            else if (i % 16 == 0 && i != 0)
            {
                DirSecCnt++;
                sector_read(fat16_ins->fd, FirstSectorofCluster + (DirSecCnt - 1) % 4, sector_buffer);
            }

            if (FatClusEntryVal == 0x00)
                break;

            memcpy(&Dir, sector_buffer + i % 16 * BYTES_PER_DIR, BYTES_PER_DIR);

            filename = (const char*)path_decode(Dir.DIR_Name);
            if (strcmp(filename, "") != 0)
                filler(buffer, filename, NULL, 0);

            i++;
        }
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
    DIR_ENTRY Dir;

    find_root(fat16_ins, &Dir, path);

    if (offset >= Dir.DIR_FileSize) //offset超过文件大小
        return 0;

    int  offset_in_sector = offset % BYTES_PER_SECTOR;
    int  OffSectorNum     = offset / BYTES_PER_SECTOR;
    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
    BYTE sector_buffer[BYTES_PER_SECTOR];
    int  i;
    ClusterN = Dir.DIR_FstClusLO;

    //找到offset偏移处的扇区
    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
    for (i = 1; i <= OffSectorNum; i++)
    {
        //换簇
        if (i % fat16_ins->Bpb.BPB_SecPerClus == 0)
        {
            first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
        }
        else //换扇区
        {
            sector_read(fat16_ins->fd, FirstSectorofCluster + i % 4, sector_buffer);
        }
    }

    //将大小为size的文件内容读进buffer（不能超过文件长度）
    if (offset + size > Dir.DIR_FileSize)
        size = Dir.DIR_FileSize - offset;

    WORD OffRemainSize = (BYTES_PER_SECTOR - offset_in_sector) % BYTES_PER_SECTOR;
    int  ReadSectorNum = size / BYTES_PER_SECTOR;
    int  RemainSize    = size % BYTES_PER_SECTOR;

    //接着上面的，一边读取数据，一边顺着数据更新扇区和簇（如果数据很大的话都要更新）
    if (OffRemainSize > 0)
    {
        memcpy(buffer, sector_buffer + offset_in_sector, OffRemainSize);
        OffSectorNum++;
    }
    //以下假设offset_in_sector == 0（事实上fuse执行的时候也保证了这一点）
    for (i = OffSectorNum; i < ReadSectorNum + OffSectorNum; i++)
    {
        //换簇
        if (i % fat16_ins->Bpb.BPB_SecPerClus == 0 && i != OffSectorNum)
        {
            first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
        }
        else //换扇区
        {
            sector_read(fat16_ins->fd, FirstSectorofCluster + i % 4, sector_buffer);
        }

        //给buffer赋值
        memcpy(buffer + (i - OffSectorNum) * BYTES_PER_SECTOR + OffRemainSize, sector_buffer, BYTES_PER_SECTOR);
    }

    //处理最后一个RemainSize
    if (RemainSize > 0)
    {
        //换簇
        if (i % fat16_ins->Bpb.BPB_SecPerClus == 0 && i != OffSectorNum)
        {
            first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
        }
        else //换扇区
        {
            sector_read(fat16_ins->fd, FirstSectorofCluster + i % 4, sector_buffer);
        }

        memcpy(buffer + (i - OffSectorNum) * BYTES_PER_SECTOR + OffRemainSize, sector_buffer, RemainSize);
    }

    return size;
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
