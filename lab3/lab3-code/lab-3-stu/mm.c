// segregated free list +  best fit + improved realloc function
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

// single word (4) or double word (8) alignment
#define ALIGNMENT 8

// rounds up to the nearest multiple of ALIGNMENT
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// Word and header/footer size (bytes)
//针对32位系统, 定义字长位4byte
#define WSIZE 4
// Double word size (bytes)
#define DSIZE 8
// Extend heap by this amount (bytes)
//为内存分配器扩充堆内存的最小单元。
#define CHUNKSIZE (1 << 12)

#define MIN_FREE_BLOCK_SIZE 12
#define PAGESIZE 8

#define MAX(x, y) ((x) > (y) ? (x) : (y))
// 未分配 a = 0
#define FREE 0
// 已分配 a = 1
#define ALLOCATED 1
// 由于内存块以8字节对齐, 块大小二进制的最低3位一定为0,
// 因此可以用最后一位来标记该块是否已被分配
// 将块大小和分配位结合返回一个值(即将size的最低位赋值为分配位)
#define PACK(size, alloc) ((size) | (alloc))
// Read a word at address p
// 分别对指针p指向的位置取值
#define GET(p) (*(unsigned int*)(p))
// Write a word at address p
// 分别对指针p指向的位置赋值
#define PUT(p, val) (*(unsigned int*)(p) = (val))
// Read the size from address p
// 分别从p指向位置获取块大小。注意 : p应该指向头部
#define GET_SIZE(p) (GET(p) & ~0x7)
// Read the allocated fields from address p
// 分别从p指向位置获取块分配位。注意 : p应该指向脚部
#define GET_ALLOC(p) (GET(p) & 0x1)
// Given block ptr bp, compute address of its header
// 返回 bp 指向块的头部
#define HDRP(bp) ((char*)(bp)-WSIZE)
// Given block ptr bp, compute address of its footer
// 返回 bp 指向块的脚部
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)
// Given block ptr bp, compute address of next blocks
// 返回与 bp 相邻的下一块
#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(((char*)(bp)-WSIZE)))
// Given block ptr bp, compute address of previous blocks
// 返回与 bp 相邻的上一块
#define PREV_BLKP(bp) ((char*)(bp)-GET_SIZE(((char*)(bp)-DSIZE)))
// Given free block ptr bp, compute the addresses of next free blocks
#define NEXT_FREE_BLKP(bp) ((char*)(bp) + WSIZE)
// Given free block ptr bp, compute the addresses of previous free blocks
#define PREV_FREE_BLKP(bp) ((char*)(bp))

static char* heap_listp        = NULL;
static char* head_of_free_list = NULL;

//  Categorize - find the free list category which fit the given size
inline char* Categorize(size_t size)
{
    int i = 0;
    for (i = 0; (size > (1 << (i + 5))) && (i < PAGESIZE - 1); i++)
        ;
    return head_of_free_list + (i * WSIZE);
}

//  Release_free_block - remove the free point from the segregated list.
inline void Release_free_block(char* p)
{
    char* root     = Categorize(GET_SIZE(HDRP(p)));
    char* prev_ptr = GET(PREV_FREE_BLKP(p));
    char* next_ptr = GET(NEXT_FREE_BLKP(p));

    if (next_ptr != NULL)
        PUT(PREV_FREE_BLKP(next_ptr), prev_ptr);

    if (prev_ptr == NULL)
        PUT(root, next_ptr);
    else
        PUT(NEXT_FREE_BLKP(prev_ptr), next_ptr);
    PUT(NEXT_FREE_BLKP(p), NULL);
    PUT(PREV_FREE_BLKP(p), NULL);
    return;
}

//  coalesce - Boundary tag coalescing. Return ptr to coalesced block
static void* coalesce(void* bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size       = GET_SIZE(HDRP(bp));
    char * root, *ptr, *next_ptr;

    if (prev_alloc && next_alloc) // all allocated
    {
    }
    else if (prev_alloc && !next_alloc) // next block is free
    {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        Release_free_block(NEXT_BLKP(bp));
        PUT(HDRP(bp), PACK(size, FREE));
        PUT(FTRP(bp), PACK(size, FREE));
    }
    else if (!prev_alloc && next_alloc) // previous block is free
    {
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        Release_free_block(PREV_BLKP(bp));
        PUT(FTRP(bp), PACK(size, FREE));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, FREE));
        bp = PREV_BLKP(bp);
    }
    else // all free
    {
        size += GET_SIZE(FTRP(NEXT_BLKP(bp))) + GET_SIZE(HDRP(PREV_BLKP(bp)));
        Release_free_block(PREV_BLKP(bp));
        Release_free_block(NEXT_BLKP(bp));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, FREE));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, FREE));
        bp = PREV_BLKP(bp);
    }

    root = Categorize(GET_SIZE(HDRP(bp)));
    for (ptr = root, next_ptr = GET(root);
         next_ptr != NULL;
         ptr = next_ptr, next_ptr = GET(NEXT_FREE_BLKP(next_ptr)))
    {
        if (GET_SIZE(HDRP(next_ptr)) >= GET_SIZE(HDRP(bp)))
            break;
    }

    if (ptr == root)
    {
        PUT(root, bp);
        PUT(NEXT_FREE_BLKP(bp), next_ptr);
        PUT(PREV_FREE_BLKP(bp), NULL);
    }
    else
    {
        PUT(NEXT_FREE_BLKP(ptr), bp);
        PUT(NEXT_FREE_BLKP(bp), next_ptr);
        PUT(PREV_FREE_BLKP(bp), ptr);
    }
    if (next_ptr != NULL)
        PUT(PREV_FREE_BLKP(next_ptr), bp);
    return bp;
}

//  extend_heap - Extend heap with free block and return its block pointer.
static void* extend_heap(size_t words)
{
    char*  bp;
    size_t size;

    size = (words % 2)
               ? (words + 1) * DSIZE
               : words * DSIZE; //compute the size fit the 16 bytes alignment

    if ((bp = mem_sbrk(size)) == (void*)-1) //move the brk pointer for bigger heap
        return NULL;

    //init the head and foot fields
    PUT(HDRP(bp), PACK(size, FREE));
    PUT(FTRP(bp), PACK(size, FREE));

    //init the prev and next free pointer fields
    PUT(NEXT_FREE_BLKP(bp), NULL);
    PUT(PREV_FREE_BLKP(bp), NULL);

    //the epilogue block
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, ALLOCATED));

    return coalesce(bp);
}

/*
    find_fit - Find a fit for a block with asize bytes. 
    Because the free list is ordered by size, so the first fit one is the best.
*/
static void* find_fit(size_t size)
{
    char* root = Categorize(size);
    for (root; root != (heap_listp - (2 * WSIZE)); root += WSIZE)
    {
        char* ptr = GET(root);
        while (ptr != NULL)
        {
            if (GET_SIZE(HDRP(ptr)) >= size)
                return ptr;
            ptr = GET(NEXT_FREE_BLKP(ptr));
        }
    }
    return NULL;
}

//  place - Place block of asize bytes at start of free block bp.
static void place(void* bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));
    Release_free_block(bp);
    if ((csize - asize) >= (MIN_FREE_BLOCK_SIZE * DSIZE))
    {
        PUT(HDRP(bp), PACK(asize, ALLOCATED));
        PUT(FTRP(bp), PACK(asize, ALLOCATED));
        bp = NEXT_BLKP(bp);

        PUT(HDRP(bp), PACK(csize - asize, FREE));
        PUT(FTRP(bp), PACK(csize - asize, FREE));

        PUT(NEXT_FREE_BLKP(bp), NULL);
        PUT(PREV_FREE_BLKP(bp), NULL);
        coalesce(bp);
    }
    else
    {
        PUT(HDRP(bp), PACK(csize, ALLOCATED));
        PUT(FTRP(bp), PACK(csize, ALLOCATED));
    }
}

/*
    mm_init - initialize the malloc package.
    The return value should be -1 if there was a problem in performing the initialization, 0 otherwise
*/
int mm_init(void)
{
    int i;

    if ((heap_listp = mem_sbrk((PAGESIZE + 4) * WSIZE)) == (void*)-1)
        return -1;

    for (i = 0; i <= PAGESIZE; i++)
    {
        PUT(heap_listp + (i * WSIZE), FREE);
    }
    PUT(heap_listp + ((PAGESIZE + 1) * WSIZE), PACK(DSIZE, ALLOCATED));
    PUT(heap_listp + ((PAGESIZE + 2) * WSIZE), PACK(DSIZE, ALLOCATED));
    PUT(heap_listp + ((PAGESIZE + 3) * WSIZE), PACK(0, ALLOCATED));

    head_of_free_list = heap_listp;
    heap_listp += ((PAGESIZE + 2) * WSIZE);

    if ((extend_heap(CHUNKSIZE / DSIZE)) == NULL)
        return -1;

    return 0;
}

/*
    mm_free - Freeing a block does nothing.
*/
void mm_free(void* bp)
{
    if (bp == 0)
        return;
    size_t size = GET_SIZE(HDRP(bp));

    PUT(HDRP(bp), PACK(size, FREE));
    PUT(FTRP(bp), PACK(size, FREE));
    PUT(NEXT_FREE_BLKP(bp), NULL);
    PUT(PREV_FREE_BLKP(bp), NULL);
    coalesce(bp);
}

/*
    mm_malloc - Allocate a block by incrementing the brk pointer.
    Always allocate a block whose size is a multiple of the alignment.
*/
void* mm_malloc(size_t size)
{
    size_t asize;
    size_t extendsize;
    char*  bp;
    if (size == 0)
        return NULL;

    if (size <= DSIZE)
    {
        asize = 2 * (DSIZE);
    }
    else
    {
        asize = (DSIZE) * ((size + (DSIZE) + (DSIZE - 1)) / (DSIZE));
    }

    if ((bp = find_fit(asize)) != NULL)
    {
        place(bp, asize);
        return bp;
    }

    /*apply new block*/
    extendsize = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extendsize / DSIZE)) == NULL)
    {
        return NULL;
    }
    place(bp, asize);
    return bp;
}

void* mm_realloc(void* ptr, size_t size)
{
    void*  oldptr = ptr;
    void*  newptr;
    size_t copySize;

    newptr = mm_malloc(size);
    if (newptr == NULL)
        return NULL;
    copySize = *(size_t*)((char*)oldptr - SIZE_T_SIZE);
    if (size < copySize)
        copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}