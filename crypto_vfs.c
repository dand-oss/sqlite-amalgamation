/*
** 12/2013 - John Lund - Created crypto vfs from test_demovfs.c
**
** 2010 April 7
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This file implements an example of a simple VFS implementation that
** omits complex features often not required or not possible on embedded
** platforms.  Code is included to buffer writes to the journal file,
** which can be a significant performance improvement on some embedded
** platforms.
**
** OVERVIEW
**
**   The code in this file implements a minimal SQLite VFS that can be
**   used on Linux and other posix-like operating systems. The following
**   system calls are used:
**
**    File-system: access(), unlink(), getcwd()
**    File IO:     open(), read(), write(), fsync(), close(), fstat()
**    Other:       sleep(), usleep(), time()
**
**   The following VFS features are omitted:
**
**     1. File locking. The user must ensure that there is at most one
**        connection to each database when using this VFS. Multiple
**        connections to a single shared-cache count as a single connection
**        for the purposes of the previous statement.
**
**     2. The loading of dynamic extensions (shared libraries).
**
**     3. Temporary files. The user must configure SQLite to use in-memory
**        temp files when using this VFS. The easiest way to do this is to
**        compile with:
**
**          -DSQLITE_TEMP_STORE=3
**
**     4. File truncation. As of version 3.6.24, SQLite may run without
**        a working xTruncate() call, providing the user does not configure
**        SQLite to use "journal_mode=truncate", or use both
**        "journal_mode=persist" and ATTACHed databases.
**
**   It is assumed that the system uses UNIX-like path-names. Specifically,
**   that '/' characters are used to separate path components and that
**   a path-name is a relative path unless it begins with a '/'. And that
**   no UTF-8 encoded paths are greater than 512 bytes in length.
**
** JOURNAL WRITE-BUFFERING
**
**   To commit a transaction to the database, SQLite first writes rollback
**   information into the journal file. This usually consists of 4 steps:
**
**     1. The rollback information is sequentially written into the journal
**        file, starting at the start of the file.
**     2. The journal file is synced to disk.
**     3. A modification is made to the first few bytes of the journal file.
**     4. The journal file is synced to disk again.
**
**   Most of the data is written in step 1 using a series of calls to the
**   VFS xWrite() method. The buffers passed to the xWrite() calls are of
**   various sizes. For example, as of version 3.6.24, when committing a
**   transaction that modifies 3 pages of a database file that uses 4096
**   byte pages residing on a media with 512 byte sectors, SQLite makes
**   eleven calls to the xWrite() method to create the rollback journal,
**   as follows:
**
**             Write offset | Bytes written
**             ----------------------------
**                        0            512
**                      512              4
**                      516           4096
**                     4612              4
**                     4616              4
**                     4620           4096
**                     8716              4
**                     8720              4
**                     8724           4096
**                    12820              4
**             ++++++++++++SYNC+++++++++++
**                        0             12
**             ++++++++++++SYNC+++++++++++
**
**   On many operating systems, this is an efficient way to write to a file.
**   However, on some embedded systems that do not cache writes in OS
**   buffers it is much more efficient to write data in blocks that are
**   an integer multiple of the sector-size in size and aligned at the
**   start of a sector.
**
**   To work around this, the code in this file allocates a fixed size
**   buffer of SQLITE_DEMOVFS_BUFFERSZ using sqlite3_malloc() whenever a
**   journal file is opened. It uses the buffer to coalesce sequential
**   writes into aligned SQLITE_DEMOVFS_BUFFERSZ blocks. When SQLite
**   invokes the xSync() method to sync the contents of the file to disk,
**   all accumulated data is written out, even if it does not constitute
**   a complete block. This means the actual IO to create the rollback
**   journal for the example transaction above is this:
**
**             Write offset | Bytes written
**             ----------------------------
**                        0           8192
**                     8192           4632
**             ++++++++++++SYNC+++++++++++
**                        0             12
**             ++++++++++++SYNC+++++++++++
**
**   Much more efficient if the underlying OS is not caching write
**   operations.
*/

// 1 = don't use crypto
// 0 = Alledged RC4 implementing CTR mode
//     see: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
#define NOCRYPTO (0)

#if !defined(__linux__)
  typedef unsigned long ULONG;
  typedef unsigned short USHORT;
  typedef unsigned char UINT8;
  typedef int STATUS;
#endif

int crypto_vfs_reads = 0;
int crypto_vfs_writes = 0;
int crypto_vfs_misses = 0;
int crypto_vfs_hits = 0;

#include <sqlite3.h>
#include <stdio.h>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
/* #include <sys/file.h> */
/* #include <sys/param.h> */
#if SQLITE_OS_UNIX
#include <unistd.h>
#endif
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#if SQLITE_OS_WIN
#include <io.h>
#include <fcntl.h>
#include "ss.h"
#endif

/*
** Size of the write buffer used by journal files in bytes.
*/
#ifndef SQLITE_DEMOVFS_BUFFERSZ
# define SQLITE_DEMOVFS_BUFFERSZ 8192
#endif

/*
** The maximum pathname length supported by this VFS.
*/
#define MAXPATHNAME 512

/*
** When using this VFS, the sqlite3_file* handles that SQLite uses are
** actually pointers to instances of type CryptoFile.
*/
typedef struct CryptoFile CryptoFile;
struct CryptoFile {
  sqlite3_file base;              /* Base class. Must be first. */
  int fd;                         /* File descriptor */

  char *aBuffer;                  /* Pointer to malloc'd buffer */
  int nBuffer;                    /* Valid bytes of data in zBuffer */
  sqlite3_int64 iBufferOfst;      /* Offset in file of zBuffer[0] */
};

// ---------------------------------------------------------------------------
// crypto functions
// Using Alledged RC5 cipher.
// Compare to libgcrypt's cipher/arcfour.c
// ---------------------------------------------------------------------------
#define RC4_BLOCK_SIZE (8192)
#define MAX_BLOCKS (16)
#define CRYPTO_KEY_LEN (256)
unsigned char crypto_key[CRYPTO_KEY_LEN] = {
0x88,0x51,0xD3,0x1A,0xFD,0x03,0x58,0x9B,0xAD,0xEB,0x0A,0xD4,0x55,0x94,0x09,0x9D,
0xC8,0xAB,0x0B,0xF1,0xC6,0x7C,0x90,0x78,0x75,0x13,0xEC,0x53,0x5B,0x9E,0x8C,0xB6,
0x0F,0xCE,0x34,0x3A,0x7C,0x9D,0x81,0x1E,0x2F,0x59,0xDF,0xBB,0x25,0x51,0x30,0xC6,
0xE5,0x2A,0x12,0x63,0xB6,0x45,0xA7,0x51,0xA1,0xD6,0x30,0x07,0xE4,0xF4,0xFB,0xAB,
0x40,0x7F,0x2B,0x1C,0x9B,0x53,0x61,0x58,0x5D,0xAB,0x81,0xA9,0xA2,0xC5,0x1C,0x76,
0xC7,0x74,0x66,0x68,0x90,0x76,0xE2,0xB1,0x2C,0xEC,0x97,0x3D,0x35,0x84,0xA6,0x09,
0xF9,0x46,0x4E,0xC1,0x87,0x66,0xAA,0x1A,0x7B,0x9D,0x31,0x19,0x24,0x33,0x52,0x5D,
0x88,0x0B,0x27,0xE5,0x5D,0xE6,0xCC,0xC1,0x43,0x4E,0xB2,0x6D,0xFD,0x34,0x07,0x8D,
0x13,0x31,0x7F,0xA2,0x61,0x5A,0xA7,0xD7,0x9A,0x3C,0x9B,0xBE,0x5A,0x14,0xF9,0x46,
0x14,0xDF,0x52,0x6F,0xE8,0x26,0x1B,0xB4,0x61,0x58,0xE6,0xCD,0xF7,0xF5,0x6E,0x8F,
0x99,0x0F,0x52,0xA7,0xC9,0x9E,0xB1,0x13,0x86,0x1B,0x4B,0x27,0x95,0xC2,0xDD,0x24,
0x4F,0x02,0x07,0xE2,0xFB,0xE6,0x2E,0x1B,0x17,0x39,0xFA,0xCA,0xF9,0xB8,0x1C,0xC7,
0x47,0x84,0x97,0xB1,0xAB,0x44,0x31,0x2E,0xE6,0xD3,0xB6,0x83,0x5D,0x97,0xD9,0x4B,
0x12,0xC7,0x4E,0xA0,0x74,0xA6,0xBC,0xD6,0x7F,0xBB,0x35,0xF0,0xB6,0xDB,0xCC,0xDB,
0x30,0xE0,0x23,0xEE,0xB0,0xBE,0x47,0xB3,0xB3,0x1F,0x2B,0xCD,0x61,0x3A,0xD8,0x37,
0x48,0x75,0x48,0xEE,0x84,0x2E,0xAB,0x92,0x04,0xB2,0x3F,0x9C,0xA3,0xCD,0x36,0x03,
};

/* --------------------------------------------------------------------
 * Keep track of the crypto state - borrowed from libgcrypt
 */
// crypto key and state - good for one crypto block
typedef struct RC4KEY_S {
    int i;
    int j;
    unsigned char state[256];
} RC4KEY ;

// crypto cache block
typedef struct RC4BLOCK_S {
    long block_addr;
    unsigned char isDirty;
    size_t size;
    RC4KEY key;
    CryptoFile *pf;
    unsigned char buffer[RC4_BLOCK_SIZE];
} RC4BLOCK;

// Keep some encrypted data blocks cached.
// the encryptor must re-encrypt from a changed byte to the
// end of a block, so keep recently used crypto blocks around
// in a LRU cache
static RC4BLOCK crypto_cache[MAX_BLOCKS];

// LRU lilo - Least Recently Used block:
// each slot in the lru is a pointer to a cache block.
// A hit gets recorded at the end of the LRU
// so that the Least Recently Used index is
// always at index 0

static RC4BLOCK* crypto_lru[MAX_BLOCKS];

// one encryption buffer (to avoid allocs)
static unsigned char crypt_buffer[RC4_BLOCK_SIZE];

static void init_crypto_cache(){
    int ix;
    RC4BLOCK empty = {(long)-1, 0, (size_t)0, {-1, -1}};
    memset(empty.buffer, 0, RC4_BLOCK_SIZE);
    for(ix=0; ix<MAX_BLOCKS; ix++){
        crypto_cache[ix] = empty;
        crypto_lru[ix] = crypto_cache + ix;
    }
}

// debug crypto cache block state dumper
void dump_cache()
{
int i;

  printf("lru={");
  for(i = 0 ; i < MAX_BLOCKS ; i++)
    printf("%d ", crypto_lru[i]);
  printf("}\n");

  for(i = 0 ; i < MAX_BLOCKS ; i++) {
    printf("%d) ba=%d, addr=%d, sz=%d, fd=%d\n",
        i,
        (int)crypto_cache[i].block_addr,
        (int)(crypto_cache[i].block_addr*RC4_BLOCK_SIZE),
        (int)crypto_cache[i].size,
        crypto_cache[i].pf != (CryptoFile *)0? crypto_cache[i].pf->fd:0
        );
  }
  printf("\n");
}

/* --------------------------------------------------------------------
 */
extern void arc4_keycopy(RC4KEY *from, RC4KEY *to)
{
    memcpy(to->state, from->state, 256);
    to->i = from->i;
    to->j = from->j;
}

/* --------------------------------------------------------------------
 * Key Scheduling Algorithm
 * Input: state - the state used to generate the keystream
 *        key - Key to use to initialize the state
 *        len - length of key in bytes
 */
extern void arc4_init(
    RC4KEY *key, int len, const unsigned char *data,
    long block_addr
){
auto int i,j=0;
unsigned char t;

    for (i=0; i < 256; ++i)
        key->state[i] = i;

    for (i=0; i < 256; ++i) {
        j = (j + key->state[i] + data[i % len] + block_addr) % 256 ;
        t = key->state[i];
        key->state[i] = key->state[j] ;
        key->state[j] = t;
    }

    key->i = 0 ;
    key->j = 0 ;
}

/* --------------------------------------------------------------------
 * Alledged RC4 Stream crypt
 * Input: state - the state used to generate the keystream
 *        out - Must be of at least "len" length
 *        len - number of bytes to generate
 */
extern void arc4(RC4KEY *key,
           const unsigned char *in,
           unsigned char *out,
           unsigned long len )
{
    auto int i=key->i, j=key->j, t ;
    auto unsigned long x;
    auto unsigned char *st = &key->state[0] ;

    for( x = 0 ; x < len ; x++ ) {
        i = (i+1) % 256 ;
        j = (j + st[i]) % 256 ;
        t = st[i] ;
        st[i] = st[j] ;
        st[j] = t ;
        out[x] = in[x] ^ st[(st[i] + st[j]) % 256] ;
    }

    key->i = i ;
    key->j = j ;
}

/*
 * moves the lru_index'th lru slot to the front of the LRU list
 */
static void move_lru_to_front(int lru_index){
    RC4BLOCK* blockptr;
    if(!lru_index) return;

    blockptr = crypto_lru[lru_index];
    while(lru_index){
        crypto_lru[lru_index] = crypto_lru[lru_index-1];
        lru_index--;
    }
    crypto_lru[0] = blockptr;
}

/*
 * find a matching cached block, and return it's lru index
 * -1 if no such block exists.
 */
static int find_cached_block(long block_addr, CryptoFile* pf){
    int result = -1;
    int lru_index;

#ifdef CRYPTO_DEBUG
    // debug
    for(lru_index=0; lru_index<MAX_BLOCKS; lru_index++){
        char ch;
        RC4BLOCK* cache_block = crypto_lru[lru_index];
        if(cache_block->block_addr < 0) ch = 'E';
        else if(cache_block->isDirty) ch = 'D';
        else ch = 'C';
        putchar(ch);
    }
    putchar('\n');
    fflush(stdout);
#endif

    for(lru_index=0; lru_index<MAX_BLOCKS; lru_index++){
        RC4BLOCK* cache_block = crypto_lru[lru_index];
        if( (cache_block->block_addr == block_addr) &&
            (cache_block->pf == pf) ){
            result = lru_index;
            break;
        }
    }
    if(result < 0) crypto_vfs_misses++;
    else           crypto_vfs_hits++;
    return result;

}

/*
 * read the disk block 'block_addr' from 'pf' into 'cache_block'
 * the block is decrypted.
 */
static int cache_read_block(
        long block_addr,
        CryptoFile* pf,
        RC4BLOCK* cache_block
){
    size_t seek_to;
    RC4KEY tmpkey;
#ifdef CRYPTO_DEBUG
    printf("cache_read_block(%ld, %p)\n", block_addr, pf);
#endif
    cache_block->pf = pf;
    cache_block->block_addr = block_addr;
    arc4_init(&(cache_block->key), CRYPTO_KEY_LEN, crypto_key, block_addr);
    memset(cache_block->buffer, 0, RC4_BLOCK_SIZE);
    seek_to = block_addr * RC4_BLOCK_SIZE;
    if(seek_to == lseek(pf->fd, seek_to, SEEK_SET)){
        crypto_vfs_reads++;
        cache_block->size = read(pf->fd, cache_block->buffer, RC4_BLOCK_SIZE);
        if(cache_block->size < 0)
            return SQLITE_IOERR_READ;

#if !NOCRYPTO
        arc4_keycopy(&(cache_block->key), &tmpkey);
        arc4(&tmpkey, cache_block->buffer, cache_block->buffer, RC4_BLOCK_SIZE);
#endif
        cache_block->isDirty = 0;
    }
    return SQLITE_OK;
}
/*
 * write the cache block 'cache_block' to disk
 */
static int cache_write_block(RC4BLOCK* cache_block){

    RC4KEY tmpkey;
    size_t seek_to;

#ifdef CRYPTO_DEBUG
    printf("cache_write_block(%ld, %p)\n", cache_block->block_addr,
          cache_block->pf);
#endif

    // encrypt the buf
#if NOCRYPTO
    memcpy(crypt_buffer, cache_block->buffer, RC4_BLOCK_SIZE);
#else
    arc4_keycopy(&(cache_block->key), &tmpkey);
    arc4(&tmpkey, cache_block->buffer, crypt_buffer, RC4_BLOCK_SIZE);
#endif

    /* write the encrypted block */
    seek_to = cache_block->block_addr * RC4_BLOCK_SIZE;
    lseek(cache_block->pf->fd, seek_to, SEEK_SET);
    crypto_vfs_writes++;
    if(RC4_BLOCK_SIZE !=
            write(cache_block->pf->fd, crypt_buffer, RC4_BLOCK_SIZE)){
        printf("Write error: %d\n, errno");
        return SQLITE_IOERR_WRITE;
    }
    cache_block->isDirty = 0;
    return SQLITE_OK;
}

/*
 * locates (or creates) a free block in the cache.  The block will be at
 * the front of the LRU, and initialized with the given arguments.
 */
static RC4BLOCK* cache_give_free_block(long block_addr, CryptoFile* pf){

    /* highest precedence to an unused block.
     * next highest precidence to a clean block (from back to front).
     * otherwise we have to write the dirty block at the back, and use that.
     */
    int lru_index;
    RC4BLOCK* cache_block;
    for(lru_index=MAX_BLOCKS-1; lru_index>=0; lru_index--){

        cache_block = crypto_lru[lru_index];

        /* unused block? */
        if(cache_block->block_addr < 0){
#ifdef CRYPTO_DEBUG
            printf("giving an unused block @%d\n", lru_index);
#endif
            break;
        }

        /* clean block? */
        if(!cache_block->isDirty){
#ifdef CRYPTO_DEBUG
            printf("giving a clean block @%d\n", lru_index);
#endif
            break;
        }
    }
    /*
     * if we didn't find one to use, we need to save the least recent used one
     * to disk, and use that.
     */
    if(lru_index < 0){
        lru_index = MAX_BLOCKS-1;
        if(SQLITE_OK != cache_write_block(crypto_lru[lru_index])){
            return 0;
        }
#ifdef CRYPTO_DEBUG
        printf("giving one we wrote back first @%d", lru_index);
#endif
    }

    /*
     * prep the block
     */
    cache_block = crypto_lru[lru_index];
    cache_block->block_addr = block_addr;
    cache_block->pf = pf;

    /*
     * move to front of lru, and return it
     */
    move_lru_to_front(lru_index);
    return cache_block;
}

// ---------------------------------------------------------------------------
// End of crypto stuff
// ---------------------------------------------------------------------------

/*
** Write directly to the file passed as the first argument. Even if the
** file has a write-buffer (CryptoFile.aBuffer), ignore it.
*/
static int cryptoDirectWrite(
  CryptoFile *p,                  /* File handle */
  const void *zBuf,               /* Buffer containing data to write */
  int iAmt,                       /* Size of data to write in bytes */
  sqlite_int64 iOfst              /* File offset to write to */
){
  int nWrite;                  /* Return value from write() */

#if SQLITE_OS_UNIX
  off_t ofst;                     /* Return value from lseek() */
#endif
#if SQLITE_OS_WIN
  size_t ofst;                     /* Return value from lseek() */
#endif

  int cacheIdx;
  size_t nRemain;                  /* remaining bytes to write through cache */
  size_t writeOffset;              /* file offset to start next write */
  int writeCnt;                    /* source count to write in current loop */
  int totWriteCnt;                 /* total bytes to write in current loop */
  size_t bOfst;                    /* write start offset in cache buffer */
  unsigned char *encrbuf;          /* write buffer for encrypted data */
#if !NOCRYPTO
  RC4KEY tmpkey;                   /* always use a temp key */
#endif

#ifdef CRYPTO_DEBUG
  printf("cryptoDirectWrite(@%ld,%d)\n", iOfst, iAmt);
#endif

  // The enryption write loop is a little more involved.
  // A crypto key is good for one cached block, no more.
  // So writes that span multiple blocks must be encrypted
  // seprately.

  nRemain = iAmt;       // how much is left to write to the file?
  writeOffset = (size_t) iOfst;  // where we are in the file

  while(nRemain > 0){

      // working with an existing block?
      long block_addr = writeOffset / RC4_BLOCK_SIZE;
      int lru_index = find_cached_block(block_addr, p);

      // if we aren't then we have to read before we can write
      RC4BLOCK* cache_block = 0;
      if(lru_index < 0){
          cache_block = cache_give_free_block(block_addr, p);
          if(!cache_block) return SQLITE_IOERR_WRITE;
          if(SQLITE_OK != cache_read_block(block_addr, p, cache_block)){
              return SQLITE_IOERR_READ;
          }
          cache_block->isDirty = 0;
      }
      else{
          cache_block = crypto_lru[lru_index];
          move_lru_to_front(lru_index);
      }

      // where are we in the cache block?
      bOfst = writeOffset % RC4_BLOCK_SIZE;  // offset into cache buffer

      // how much we can write through this cache buffer?
      if((size_t)(bOfst + nRemain) > RC4_BLOCK_SIZE) {
          writeCnt = RC4_BLOCK_SIZE - bOfst;
      }
      else {
          writeCnt = nRemain;
      }

      if( writeCnt > 0 ){

          // do we need to add space to the cache block?
          if( (bOfst + writeCnt) > cache_block->size ){
             cache_block->size = bOfst + writeCnt;
          }
          memcpy(cache_block->buffer + bOfst,
                 (unsigned char*)zBuf + (writeOffset - iOfst),
                 writeCnt);
          cache_block->isDirty = 1;
      }
      nRemain -= writeCnt;
      if(nRemain > 0) writeOffset += writeCnt;
      else nRemain = 0;
  }
  return SQLITE_OK;
}

/*
** Flush the contents of the CryptoFile Buffer buffer to disk. This is a
** no-op if this particular file does not have a buffer (i.e. it is not
** a journal file) or if the buffer is currently empty.
*/
static int cryptoFlushBuffer(CryptoFile *p){
  int rc = SQLITE_OK;
  if( p->nBuffer ){
    rc = cryptoDirectWrite(p, p->aBuffer, p->nBuffer, p->iBufferOfst);
    p->nBuffer = 0;
  }
  return rc;
}

/*
** Close a file.
*/
static int cryptoClose(sqlite3_file *pFile){
  int rc;
  CryptoFile *p = (CryptoFile*)pFile;
  rc = cryptoFlushBuffer(p);
  sqlite3_free(p->aBuffer);
  close(p->fd);
  return rc;
}

/*
** Read data from a file.
*/
static int cryptoRead(
  sqlite3_file *pFile,
  void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  int rc;                         /* Return code from cryptoFlushBuffer() */

  int cacheIdx;
  size_t nRemain;                  /* remaining bytes to write through cache */
  size_t readOffset;               /* file offset to start next read */
  int readCnt;                     /* source count to read in current loop */
  int totReadCnt = 0;              /* total bytes ready */
  size_t bOfst;                    /* read start offset in cache buffer */

  CryptoFile *p = (CryptoFile*)pFile;

#ifdef CRYPTO_DEBUG
  printf("cryptoRead(@%ld, %d)\n", iOfst, iAmt);
#endif

  /* Flush any data in the write buffer to disk in case this operation
  ** is trying to read data the file-region currently cached in the buffer.
  ** It would be possible to detect this case and possibly save an
  ** unnecessary write here, but in practice SQLite will rarely read from
  ** a journal file when there is data cached in the write-buffer.
  */
  rc = cryptoFlushBuffer(p);
  if( rc!=SQLITE_OK ){
    return rc;
  }

  nRemain = iAmt;       // how much is left to read from the file?
  readOffset = (size_t) iOfst;   // where we are in the file

  while(nRemain > 0){

      size_t block_addr = readOffset / RC4_BLOCK_SIZE;

      // do we have this block in cache?
      int lru_index = find_cached_block(block_addr, p);

      // no, get it there
      RC4BLOCK* cache_block = 0;
      if(lru_index < 0){
          cache_block = cache_give_free_block(block_addr, p);
          if(!cache_block) return SQLITE_IOERR_WRITE;
          if(SQLITE_OK != cache_read_block(block_addr, p, cache_block)){
              return SQLITE_IOERR_READ;
          }
      }
      else {
          cache_block = crypto_lru[lru_index];
      }

      // figure out where we are in the cache block
      bOfst = readOffset % RC4_BLOCK_SIZE;

      // how many bytes can we read?
      if((size_t)(bOfst + nRemain) >= RC4_BLOCK_SIZE) {
          readCnt = RC4_BLOCK_SIZE - bOfst;
      }
      else {
          readCnt = nRemain ;
      }
      memcpy((unsigned char*)zBuf + (readOffset-iOfst),
             cache_block->buffer + bOfst,
             readCnt);

      // update the request params - see if we're done reading
      totReadCnt += readCnt ;
      nRemain -= readCnt;
      if( nRemain > 0) readOffset += readCnt;
      else nRemain = 0;
  }
  return totReadCnt == iAmt ? SQLITE_OK : SQLITE_IOERR_SHORT_READ;
}

/*
** Write data to a crash-file.
*/
static int cryptoWrite(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  int rc;
  CryptoFile *p = (CryptoFile*)pFile;

  if( p->aBuffer ){
    char *z = (char *)zBuf;       /* Pointer to remaining data to write */
    int n = iAmt;                 /* Number of bytes at z */
    sqlite3_int64 i = iOfst;      /* File offset to write to */

    while( n>0 ){
      int nCopy;                  /* Number of bytes to copy into buffer */

      /* If the buffer is full, or if this data is not being written directly
      ** following the data already buffered, flush the buffer. Flushing
      ** the buffer is a no-op if it is empty.
      */
      if( p->nBuffer==SQLITE_DEMOVFS_BUFFERSZ || p->iBufferOfst+p->nBuffer!=i ){
        int rc = cryptoFlushBuffer(p);
        if( rc!=SQLITE_OK ){
          return rc;
        }
      }
      assert( p->nBuffer==0 || p->iBufferOfst+p->nBuffer==i );
      p->iBufferOfst = i - p->nBuffer;

      /* Copy as much data as possible into the buffer. */
      nCopy = SQLITE_DEMOVFS_BUFFERSZ - p->nBuffer;
      if( nCopy>n ){
        nCopy = n;
      }
      memcpy(&p->aBuffer[p->nBuffer], z, nCopy);
      p->nBuffer += nCopy;

      n -= nCopy;
      i += nCopy;
      z += nCopy;
    }
  }else{
    rc = cryptoDirectWrite(p, zBuf, iAmt, iOfst);
    return rc;
  }

  return SQLITE_OK;
}

/*
** Truncate a file. This is a no-op for this VFS (see header comments at
** the top of the file).
*/
static int cryptoTruncate(sqlite3_file *pFile, sqlite_int64 size){
#if 0
  if( ftruncate(((CryptoFile *)pFile)->fd, size) ) return SQLITE_IOERR_TRUNCATE;
#endif
  return SQLITE_OK;
}

/*
** Sync the contents of the file to the persistent media.
*/
static int cryptoSync(sqlite3_file *pFile, int flags){
#ifdef CRYPTO_DEBUG
  printf("cryptoSync()\n");
#endif
  CryptoFile *p = (CryptoFile*)pFile;
  int rc;

  // write all dirty blocks, for this file, back to disk
  int lru_index;
  for(lru_index=0; lru_index < MAX_BLOCKS; lru_index++){
      RC4BLOCK* cache_block = crypto_lru[lru_index];
      if(cache_block->isDirty && (cache_block->pf == p)){
          int rc = cache_write_block(cache_block);
          if(rc != SQLITE_OK) return rc;
          cache_block->isDirty = 0;
      }
  }

  rc = cryptoFlushBuffer(p);
  if( rc!=SQLITE_OK ){
    return rc;
  }

#if defined(__linux__)
  rc = fsync(p->fd);
#endif
  return (rc==0 ? SQLITE_OK : SQLITE_IOERR_FSYNC);
}

/*
** Write the size of the file in bytes to *pSize.
*/
static int cryptoFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  CryptoFile *p = (CryptoFile*)pFile;
  int rc;                         /* Return code from fstat() call */
#if SQLITE_OS_UNIX
  struct stat sStat;              /* Output of fstat() call */
#endif
#if SQLITE_OS_WIN
  struct stat sStat;              /* Output of fstat() call */
#endif

  /* Flush the contents of the buffer to disk. As with the flush in the
  ** cryptoRead() method, it would be possible to avoid this and save a write
  ** here and there. But in practice this comes up so infrequently it is
  ** not worth the trouble.
  */
  rc = cryptoFlushBuffer(p);
  if( rc!=SQLITE_OK ){
    return rc;
  }

  rc = fstat(p->fd, &sStat);
  if( rc!=0 ){
    return SQLITE_IOERR_FSTAT;
  }
  *pSize = sStat.st_size;
  return SQLITE_OK;
}

/*
** Locking functions. The xLock() and xUnlock() methods are both no-ops.
** The xCheckReservedLock() always indicates that no other process holds
** a reserved lock on the database file. This ensures that if a hot-journal
** file is found in the file-system it is rolled back.
*/
static int cryptoLock(sqlite3_file *pFile, int eLock){
  return SQLITE_OK;
}
static int cryptoUnlock(sqlite3_file *pFile, int eLock){
  return SQLITE_OK;
}
static int cryptoCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  *pResOut = 0;
  return SQLITE_OK;
}

/*
** No xFileControl() verbs are implemented by this VFS.
*/
static int cryptoFileControl(sqlite3_file *pFile, int op, void *pArg){
  return SQLITE_NOTFOUND;
}

/*
** The xSectorSize() and xDeviceCharacteristics() methods. These two
** may return special values allowing SQLite to optimize file-system
** access to some extent. But it is also safe to simply return 0.
*/
static int cryptoSectorSize(sqlite3_file *pFile){
  return 0;
}
static int cryptoDeviceCharacteristics(sqlite3_file *pFile){
  return 0;
}

/*
** Open a file handle.
*/
static int cryptoOpen(
  sqlite3_vfs *pVfs,              /* VFS */
  const char *zName,              /* File to open, or 0 for a temp file */
  sqlite3_file *pFile,            /* Pointer to CryptoFile struct to populate */
  int flags,                      /* Input SQLITE_OPEN_XXX flags */
  int *pOutFlags                  /* Output SQLITE_OPEN_XXX flags (or NULL) */
){
  static const sqlite3_io_methods cryptoio = {
    1,                            /* iVersion */
    cryptoClose,                    /* xClose */
    cryptoRead,                     /* xRead */
    cryptoWrite,                    /* xWrite */
    cryptoTruncate,                 /* xTruncate */
    cryptoSync,                     /* xSync */
    cryptoFileSize,                 /* xFileSize */
    cryptoLock,                     /* xLock */
    cryptoUnlock,                   /* xUnlock */
    cryptoCheckReservedLock,        /* xCheckReservedLock */
    cryptoFileControl,              /* xFileControl */
    cryptoSectorSize,               /* xSectorSize */
    cryptoDeviceCharacteristics     /* xDeviceCharacteristics */
  };

  CryptoFile *p = (CryptoFile*)pFile; /* Populate this structure */
  int oflags = 0;                 /* flags to pass to open() call */
  char *aBuf = 0;
  static int first_time = 1;

  if(first_time){
      init_crypto_cache();
      first_time = 0;
  }

  if( zName==0 ){
    return SQLITE_IOERR;
  }

  if( flags&SQLITE_OPEN_MAIN_JOURNAL ){
    aBuf = (char *)sqlite3_malloc(SQLITE_DEMOVFS_BUFFERSZ);
    if( !aBuf ){
      return SQLITE_NOMEM;
    }
  }

  if( flags&SQLITE_OPEN_EXCLUSIVE ) oflags |= O_EXCL;
  if( flags&SQLITE_OPEN_CREATE )    oflags |= O_CREAT;
  if( flags&SQLITE_OPEN_READONLY )  oflags |= O_RDONLY;
  if( flags&SQLITE_OPEN_READWRITE ) oflags |= O_RDWR;

#if SQLITE_OS_WIN
  oflags |= _O_BINARY; // | _O_RANDOM;
#endif

  memset(p, 0, sizeof(CryptoFile));
  p->fd = open(zName, oflags, 0600);
  if( p->fd<0 ){
    sqlite3_free(aBuf);
    return SQLITE_CANTOPEN;
  }
  p->aBuffer = aBuf;

  if( pOutFlags ){
    *pOutFlags = flags;
  }
  p->base.pMethods = &cryptoio;
  return SQLITE_OK;
}

/*
** Delete the file identified by argument zPath. If the dirSync parameter
** is non-zero, then ensure the file-system modification to delete the
** file has been synced to disk before returning.
*/
static int cryptoDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
  int rc;                         /* Return code */


  rc = unlink((char*)zPath);

  if( rc!=0 /* && errno==ENOENT */ ) return SQLITE_OK;

  if( rc==0 && dirSync ){
    int dfd;                      /* File descriptor open on directory */
    int i;                        /* Iterator variable */
    char zDir[MAXPATHNAME+1];     /* Name of directory containing file zPath */

    /* Figure out the directory name from the path of the file deleted. */
    sqlite3_snprintf(MAXPATHNAME, zDir, "%s", zPath);
    zDir[MAXPATHNAME] = '\0';
    for(i=strlen(zDir); i>1 && zDir[i]!='/'; i++);
    zDir[i] = '\0';

    /* Open a file-descriptor on the directory. Sync. Close. */
    dfd = open(zDir, O_RDONLY, 0);
    if( dfd<0 ){
      rc = -1;
    }else{
#if defined(__linux__)
      rc = fsync(dfd);
#else
      rc = 0;
#endif
      close(dfd);
    }
  }
  return (rc==0 ? SQLITE_OK : SQLITE_IOERR_DELETE);
}

#ifndef F_OK
# define F_OK 0
#endif
#ifndef R_OK
# define R_OK 4
#endif
#ifndef W_OK
# define W_OK 2
#endif

/*
** Query the file-system to see if the named file exists, is readable or
** is both readable and writable.
*/
static int cryptoAccess(
  sqlite3_vfs *pVfs,
  const char *zPath,
  int flags,
  int *pResOut
){
    int rc;                                   /* access() return code */
    struct stat statbuf;

    assert( flags==SQLITE_ACCESS_EXISTS      /* access(zPath, F_OK) */
         || flags==SQLITE_ACCESS_READ         /* access(zPath, R_OK) */
         || flags==SQLITE_ACCESS_READWRITE    /* access(zPath, R_OK|W_OK) */
     );

     /* run a stat */
     memset(&statbuf, 0, sizeof(statbuf));
     rc = stat((char*)zPath, &statbuf);

     /* if checking existence */
     if(rc == -1 && flags == SQLITE_ACCESS_EXISTS) rc = -1;

     /* just assume everything else is ok */
     else return rc = 0;
     *pResOut = (rc==0);
  return SQLITE_OK;
}

/*
** Argument zPath points to a nul-terminated string containing a file path.
** If zPath is an absolute path, then it is copied as is into the output
** buffer. Otherwise, if it is a relative path, then the equivalent full
** path is written to the output buffer.
**
** This function assumes that paths are UNIX style. Specifically, that:
**
**   1. Path components are separated by a '/'. and
**   2. Full paths begin with a '/' character.
*/
static int cryptoFullPathname(
  sqlite3_vfs *pVfs,              /* VFS */
  const char *zPath,              /* Input path (possibly a relative path) */
  int nPathOut,                   /* Size of output buffer in bytes */
  char *zPathOut                  /* Pointer to output buffer */
){
  char zDir[MAXPATHNAME+1];

#if SQLITE_OS_WINNT
  if( strlen(zPath) > 1 && zPath[1]==':' ){
#else
  if( zPath[0]=='/' ){
#endif
    zDir[0] = '\0';
    strncpy(zPathOut, zPath, nPathOut);
  }else{
    if( getcwd(zDir, sizeof(zDir))==0 ){
      return SQLITE_IOERR;
    }
    sqlite3_snprintf(nPathOut, zPathOut, "%s/%s", zDir, zPath);
  }
  zDir[MAXPATHNAME] = '\0';
  zPathOut[nPathOut-1] = '\0';

  return SQLITE_OK;
}

/*
** The following four VFS methods:
**
**   xDlOpen
**   xDlError
**   xDlSym
**   xDlClose
**
** are supposed to implement the functionality needed by SQLite to load
** extensions compiled as shared objects. This simple VFS does not support
** this functionality, so the following functions are no-ops.
*/
static void *cryptoDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  return 0;
}
static void cryptoDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  sqlite3_snprintf(nByte, zErrMsg, "Loadable extensions are not supported");
  zErrMsg[nByte-1] = '\0';
}
static void (*cryptoDlSym(sqlite3_vfs *pVfs, void *pH, const char *z))(void){
  return 0;
}
static void cryptoDlClose(sqlite3_vfs *pVfs, void *pHandle){
  return;
}

/*
** Parameter zByte points to a buffer nByte bytes in size. Populate this
** buffer with pseudo-random data.
*/
static int cryptoRandomness(sqlite3_vfs *pVfs, int nByte, char *zByte){
  return SQLITE_OK;
}

/*
** Sleep for at least nMicro microseconds. Return the (approximate) number
** of microseconds slept for.
*/
static int cryptoSleep(sqlite3_vfs *pVfs, int nMicro){
#if SQLITE_OS_WIN
    Sleep(nMicro / 1000000);
#else
#if defined(__linux__)
    sleep(nMicro / 1000000);
    usleep(nMicro % 1000000);
#else
  sleep_processor(nMicro/1000);
#endif
#endif
  return nMicro;
}

/*
** Set *pTime to the current UTC time expressed as a Julian day. Return
** SQLITE_OK if successful, or an error code otherwise.
**
**   http://en.wikipedia.org/wiki/Julian_day
**
** This implementation is not very good. The current time is rounded to
** an integer number of seconds. Also, assuming time_t is a signed 32-bit
** value, it will stop working some time in the year 2038 AD (the so-called
** "year 2038" problem that afflicts systems that store time this way).
*/
static int cryptoCurrentTime(sqlite3_vfs *pVfs, double *pTime){
  time_t t = time(0);
  *pTime = t/86400.0 + 2440587.5;
  return SQLITE_OK;
}

/*
** This function returns a pointer to the VFS implemented in this file.
** To make the VFS available to SQLite:
**
**   sqlite3_vfs_register(sqlite3_cryptovfs(), 0);
*/
sqlite3_vfs *sqlite3_cryptovfs(void){
  static sqlite3_vfs cryptovfs = {
    1,                            /* iVersion */
    sizeof(CryptoFile),             /* szOsFile */
    MAXPATHNAME,                  /* mxPathname */
    0,                            /* pNext */
    "crypto",                       /* zName */
    0,                            /* pAppData */
    cryptoOpen,                     /* xOpen */
    cryptoDelete,                   /* xDelete */
    cryptoAccess,                   /* xAccess */
    cryptoFullPathname,             /* xFullPathname */
    cryptoDlOpen,                   /* xDlOpen */
    cryptoDlError,                  /* xDlError */
    cryptoDlSym,                    /* xDlSym */
    cryptoDlClose,                  /* xDlClose */
    cryptoRandomness,               /* xRandomness */
    cryptoSleep,                    /* xSleep */
    cryptoCurrentTime,              /* xCurrentTime */
  };
  return &cryptovfs;
}

/* this is a hook that can be used to define the RC4 encryption as
 * sqlit3e custom function
 * typical usage: select arc4(<key>, <value>)
 */

void arc4_sqlite3_function(
    sqlite3_context* ctx, int argc, sqlite3_value **argv
){
    RC4KEY key;
    int key_len;
    const unsigned char* key_data;
    const unsigned char* in_data;
    int in_len;
    unsigned char* out_data;

    if(argc == 2){
	key_data = sqlite3_value_blob(argv[0]);
	key_len  = sqlite3_value_bytes(argv[0]);
	in_data  = sqlite3_value_blob(argv[1]);
	in_len   = sqlite3_value_bytes(argv[1]);
	out_data = sqlite3_malloc(in_len);
	arc4_init(&key, key_len, key_data, 801193);
	arc4(&key, in_data, out_data, in_len);
	sqlite3_result_blob(ctx, out_data, in_len, sqlite3_free);
    } else {
	sqlite3_result_null(ctx);
    }
}

#ifdef SQLITE_TEST

#include <tcl.h>

#if SQLITE_OS_UNIX
static int register_cryptovfs(
  ClientData clientData, /* Pointer to sqlite3_enable_XXX function */
  Tcl_Interp *interp,    /* The TCL interpreter that invoked this command */
  int objc,              /* Number of arguments */
  Tcl_Obj *CONST objv[]  /* Command arguments */
){
  sqlite3_vfs_register(sqlite3_cryptovfs(), 1);
  return TCL_OK;
}
static int unregister_cryptovfs(
  ClientData clientData, /* Pointer to sqlite3_enable_XXX function */
  Tcl_Interp *interp,    /* The TCL interpreter that invoked this command */
  int objc,              /* Number of arguments */
  Tcl_Obj *CONST objv[]  /* Command arguments */
){
  sqlite3_vfs_unregister(sqlite3_cryptovfs());
  return TCL_OK;
}

/*
** Register commands with the TCL interpreter.
*/
int Sqlitetest_cryptovfs_Init(Tcl_Interp *interp){
  Tcl_CreateObjCommand(interp, "register_cryptovfs", register_cryptovfs, 0, 0);
  Tcl_CreateObjCommand(interp, "unregister_cryptovfs", unregister_cryptovfs, 0, 0);
  return TCL_OK;
}

#else
int Sqlitetest_cryptovfs_Init(Tcl_Interp *interp){ return TCL_OK; }
#endif

#endif /* SQLITE_TEST */
