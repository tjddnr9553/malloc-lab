/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// #define BEST_FIT
#define NEXT_FIT

void *heap_listp; // heap_listp 초기화(힙의 시작지점을 가리킴 -> 초기화가 완료되면 프롤로그 헤더와 푸터 사이에 위치함)
void *next_fitp;
void *best_fitp;

static void *find_fit(size_t asize)
{
    // Next-fit 방법 : 이전 검색이 종료된 지점부터 순회하면서 적당한 크기를 찾아 할당하는 방법
#ifdef NEXT_FIT
    void *bp; // next_fit 포인터
    void *old_ptr = next_fitp;
    for (bp = next_fitp; GET_SIZE(HDRP(bp)); bp = NEXT_BLKP(bp)) // 프롤로그 블록부터 시작해서 블록사이즈가 0보다 큰 경우 순회하고, 순회 후 다음 블럭의 시작주소로 이동
    {
        if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) // 헤더 블록을 확인해서 할당되지 않았고, 그 블록의 크기가 필요한 크기보다 크거나 같은 경우
        {
            next_fitp = NEXT_BLKP(bp);
            return bp;
        }
    }

    for (bp = heap_listp; bp < old_ptr; bp = NEXT_BLKP(bp)) // 프롤로그 블록부터 시작해서 블록사이즈가 0보다 큰 경우 순회하고, 순회 후 다음 블럭의 시작주소로 이동
    {
        if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) // 헤더 블록을 확인해서 할당되지 않았고, 그 블록의 크기가 필요한 크기보다 크거나 같은 경우
        {
            next_fitp = NEXT_BLKP(bp);
            return bp;
        }
    }
    return NULL; // 적당한 공간이 없다면 NULL을 반환
#elif defined(BEST_FIT)
    void *bp;
    void *best_fitp = NULL; // 가장 적합한 블록을 기억하기 위한 포인터 초기화

    for (bp = heap_listp; GET_SIZE(HDRP(bp)); bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp))))
        {
            if (best_fitp == NULL || GET_SIZE(HDRP(best_fitp)) > GET_SIZE(HDRP(bp)))
                best_fitp = bp; // 현재 블록이 가장 적합한 블록이라면 best_fitp 갱신
        }
    }

    if (best_fitp != NULL)
        return best_fitp; // 가장 적합한 블록 반환
    else
        return NULL; // 적당한 공간이 없다면 NULL 반환
#else // First-fit 방법 : 블록의 처음부터 순회하면서 적당한 크기가 있다면 할당하는 방법
    void *bp;
    for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) // 프롤로그 블록부터 시작해서 블록사이즈가 0보다 큰 경우 순회하고, 순회 후 다음 블럭의 시작주소로 이동
    {
        if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) // 헤더 블록을 확인해서 할당되지 않았고, 그 블록의 크기가 필요한 크기보다 크거나 같은 경우
        {
            return bp;
        }
    }
    return NULL; // 적당한 공간이 없다면 NULL을 반환
#endif
}

static void *place(void *p, size_t asize) // 할당해주려고 기존 블럭(공간 제공자) , 할당하려고 하는 크기
{
    size_t csize = GET_SIZE(HDRP(p)); // 할당해주기 전의 기존 블럭 사이즈를 저장해둠

    if ((csize - asize) >= (2 * DSIZE)) // 최소로 필요한 헤더, 푸터, 데이터의 크기 16바이트가 보장된다면
    {
        PUT(HDRP(p), PACK(asize, 1));         // 할당받은 블럭의 헤더에 블록 사이즈와 allocated를 표시
        PUT(FTRP(p), PACK(asize, 1));         // 할당받은 블럭의 푸터에 블록 사이즈와 allocated를 표시
        p = NEXT_BLKP(p);                     // 배치를 하고 다음 블럭으로 넘어감
        PUT(HDRP(p), PACK(csize - asize, 0)); // 다음 블럭의 헤더에 기존 블럭의 크기에서 할당해준만큼 빼고 free상태 표시
        PUT(FTRP(p), PACK(csize - asize, 0)); // 다음 블럭의 푸터에 기존 블럭의 크기에서 할당해준만큼 빼고 free상태 표시
    }
    else // 최소로 필요한 헤더, 푸터, 데이터의 크기 16바이트가 보장되지 않는다면
    {
        PUT(HDRP(p), PACK(csize, 1));
        PUT(FTRP(p), PACK(csize, 1));
    }
    return p;
}

static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))); // 이전 블록의 할당여부를 리턴
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp))); // 다음 블록의 할당여부를 리턴
    size_t size = GET_SIZE(HDRP(bp));                   // 현재 블록 포인터의 헤데에서 블록의 크기를 받아옴

    // CASE 1
    if (prev_alloc && next_alloc)
    { // 앞, 뒤 블록이 모두 할당된 경우
        return bp;
    }

    // CASE 2
    else if (prev_alloc && !next_alloc)
    {                                          // 다음 블록만 해제된 경우(현재 블록과 다음 블록을 연결)
        size += GET_SIZE(HDRP(NEXT_BLKP(bp))); // 다음 블록의 크기를 사이즈에 더함(현재의 사이즈와 다음 해제되어있는 블록의 크기를 더함)
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    // CASE 3
    else if (!prev_alloc && next_alloc)
    {                                          // 이전 블록만 해제된 경우(현재 블록과 이전 블록을 연결)
        size += GET_SIZE(HDRP(PREV_BLKP(bp))); // 이전 블록의 크기를 사이즈에 더함(현재의 사이즈와 이전에 해제되어있는 블록의 크기를 더함)
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

    // CASE 4
    else
    {                                                                          // 앞, 뒤 블록 모두 해제된 경우(현재 블록과 앞,뒤 블록 모두 연결)
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp))); // 앞, 뒤 블록의 크기를 사이즈에 더함
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
#ifdef NEXT_FIT
    next_fitp = bp;
#endif

#ifdef BEST_FIT
    best_fitp = bp;
#endif
    return bp;
}

static void *extended_heap(size_t words)
{
    char *bp; // 블록 포인터
    size_t size;

    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
    if ((long)(bp = mem_sbrk(size)) == -1)
    {
        return NULL;
    }
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
    return coalesce(bp);
}

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
    {
        return -1;
    }
    PUT(heap_listp, 0);                            // 패딩 설정
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); // 프롤로그 헤더
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1)); // 프롤로그 푸터
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));     // 에필로그 헤더
    heap_listp += (2 * WSIZE);                     // 초기 heap_listp는 프롤로그 헤더와 프롤로그 푸터 사이에 위치함(프롤로그는 페이로드가 없음)
#ifdef NEXT_FIT
    next_fitp = heap_listp;
#endif
#ifdef BEST_FIT
    best_fitp = heap_listp;
#endif
    if (extended_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;
    return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;      // 조정할 블록의 크기
    size_t extendsize; // 알맞은 크기의 할당 공간이 없다면 힙 영역을 확장시킬 크기
    char *bp;

    if (size == 0) // 사이즈가 0으로 할당을 시도하면 무시해버림
        return NULL;

    if (size <= DSIZE)     // 더블 워드 사이즈(8바이트)보다 요구하는 크기가 작다면
        asize = 2 * DSIZE; // 패딩, 프롤로그(헤더, 푸터), 에필로그를 확보하기 위해서 최소 4워드(16바이트)를 할당해야함
    else
        asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE); // 8의 배수를 보장하기 위해서 올림 연산을 수행

    if ((bp = find_fit(asize)) != NULL) // 가용한 블록 중에서 적당한 공간이 있는 경우
    {
        place(bp, asize);
#ifdef NEXT_FIT
        next_fitp = bp;
#endif
#ifdef BEST_FIT
        best_fitp = bp;
#endif
        return bp;
    }

    // 적당한 공간이 없다면
    extendsize = MAX(asize, CHUNKSIZE); // 사용자가 요구한 보정된 크기와 CHUNKSIZE를 비교해서 더 큰 값을 지정
    if ((bp = extended_heap(extendsize / WSIZE)) == NULL)
        return NULL;
    place(bp, asize);
#ifdef NEXT_FIT
    next_fitp = bp;
#endif
#ifdef BEST_FIT
    best_fitp = bp;
#endif
    return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    // CASE 1
    if (ptr == NULL)            // 포인터가 없다면
        return mm_malloc(size); // 메모리 할당함

    // CASE 2
    if (size <= 0) // 사이즈 0으로 realloc 요청하면
    {
        mm_free(ptr); // 메모리 반환시킴
        return NULL;
    }

    void *newptr;
    size_t copySize = GET_SIZE(HDRP(ptr)); // 재할당하려는 블록의 사이즈

    if (size + DSIZE <= copySize) // (재할당 하려는 블록 사이즈 + 8 bytes(Header + Footer)) <= 현재 블록 사이즈
    {
        return ptr; // 현재 블록에 재할당해도 문제 없기 때문에, 포인터만 반환
    }
    else // (재할당 하려는 블록 사이즈 + 8 bytes) > 현재 블록 사이즈
         // 경우에 따라서 인접 Free block을 활용하는 방안과, 새롭게 할당하는 방안을 이용해야 함
    {
        size_t next_size = copySize + GET_SIZE(HDRP(NEXT_BLKP(ptr))); // 현재 블록 사이즈 + 다음 블록 사이즈 = next_size
        size_t prev_size = copySize + GET_SIZE(HDRP(PREV_BLKP(ptr))); // 현재 블록 사이즈 + 다음 블록 사이즈 = next_size

        if (!GET_ALLOC(HDRP(NEXT_BLKP(ptr))) && (size + DSIZE <= next_size))
        // 다음 블록이 Free block이고, (재할당 하려는 블록의 사이즈 + 8 bytes) <= (현재 블록 사이즈 + 다음 블록 사이즈)
        // 현재 블록과 다음 블록을 하나의 블록으로 취급해도 크기의 문제가 발생하지 않음
        // malloc을 하지 않아도 됨 -> 메모리 공간 및 시간적 이득을 얻을 수 있음
        {
            void *next_ptr = NEXT_BLKP(ptr);
            PUT(HDRP(ptr), PACK(next_size, 1));      // 현재 블록의 Header Block에, (현재 블록 사이즈 + 다음 블록 사이즈) 크기와 Allocated 상태 기입
            PUT(FTRP(next_ptr), PACK(next_size, 1)); // 다음 블록의 Footer Block에, (현재 블록 사이즈 + 다음 블록 사이즈) 크기와 Allocated 상태 기입
#ifdef NEXT_FIT
            next_fitp = ptr; // next_fit 사용을 위한 포인터 동기화
#endif
#ifdef BEST_FIT
            best_fitp = ptr;
#endif
            return ptr;
        }
        else if (!GET_ALLOC(HDRP(PREV_BLKP(ptr))) && (size + DSIZE <= prev_size))
        // 다음 블록이 Free block이고, (재할당 하려는 블록의 사이즈 + 8 bytes) <= (현재 블록 사이즈 + 다음 블록 사이즈)
        // 현재 블록과 다음 블록을 하나의 블록으로 취급해도 크기의 문제가 발생하지 않음
        // malloc을 하지 않아도 됨 -> 메모리 공간 및 시간적 이득을 얻을 수 있음
        {
            void *prev_ptr = PREV_BLKP(ptr);         // 이전 블록의 bp
            PUT(HDRP(prev_ptr), PACK(prev_size, 1)); // 이전 블록의 Header Block에, (현재 블록 사이즈 + 다음 블록 사이즈) 크기와 Allocated 상태 기입
            PUT(FTRP(ptr), PACK(prev_size, 1));      // 현재 블록의 Footer Block에, (현재 블록 사이즈 + 다음 블록 사이즈) 크기와 Allocated 상태 기입
            memmove(prev_ptr, ptr, copySize);

#ifdef NEXT_FIT
            next_fitp = ptr; // next_fit 사용을 위한 포인터 동기화
#endif
#ifdef BEST_FIT
            best_fitp = ptr;
#endif
            return prev_ptr;
        }
        // else if (!GET_ALLOC(HDRP(PREV_BLKP(oldptr))) && ())
        else // 위 케이스에 모두 해당되지 않아, 결국 malloc을 해야 하는 경우
        {
            newptr = mm_malloc(size + DSIZE); // (할당하려는 크기 + 8 bytes)만큼 새롭게 할당
            if (newptr == NULL)               // 새로 할당한 주소가 NULL일 경우 (예외처리)
            {
                return NULL;
            }
            memmove(newptr, ptr, size + DSIZE); // payload 복사
#ifdef NEXT_FIT
            next_fitp = newptr; // next_fit 사용을 위한 포인터 동기화
#endif
#ifdef BEST_FIT
            best_fitp = newptr;
#endif
            mm_free(ptr);  // 기존의 블록은 Free block으로 바꾼다
            return newptr; // 새롭게 할당된 주소의 포인터를 반환
        }
    }
}
