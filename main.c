#include <stdio.h>
#define Swap(x) (((x >> 24) & 0xff) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) | ((x << 24) & 0xff000000))
#define time _time
#include <time.h>
#undef time
unsigned long time(){
  unsigned long ts;
  __clock_gettime(0, &ts);
  return ts;
}
typedef struct {
    unsigned long digest[8];
    unsigned int lo;
    unsigned int hi;
    unsigned int data[64];
    unsigned int local;
    unsigned int digestsize;
} SHA;
SHA sha256 = {{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}, 0, 0, {0}, 0, 32};
void RND(int a, int b, int c, unsigned long *d, int e, int f, int g, unsigned long *h, int ki, unsigned long *W){
    static int i = 0;
    i &= 63;
    int t = *h + (((((e & 0xffffffff) >> 6) | (e << 26)) & 0xffffffff) ^ ((((e & 0xffffffff) >> 11) | (e << 21)) & 0xffffffff) ^ ((((e & 0xffffffff) >> 25) | (e << 7)) & 0xffffffff)) + (g ^ (e & (f ^ g))) + ki + W[i++];
    *d = (*d + t) & 0xffffffff;
    *h = (t + (((((a & 0xffffffff) >> 2) | (a << 30)) & 0xffffffff) ^ ((((a & 0xffffffff) >> 13) | (a << 19)) & 0xffffffff) ^ ((((a & 0xffffffff) >> 22) | (a << 10)) & 0xffffffff)) + (((a | b) & c) | (a & b))) & 0xffffffff;
}
void transform(SHA *_sha) {
    unsigned long W[64] = {0};
    unsigned long ss[8];
    int d[64];
    for(int i = 0; i < 64; i ++) d[i] = _sha -> data[i];
    for(int i = 0; i < 8; i ++) ss[i] = _sha -> digest[i];
    for(int i = 0; i < 16; i ++) W[i] = (d[4 * i] << 24) + (d[4 * i + 1] << 16) + (d[4 * i + 2] << 8) + d[4 * i + 3];
    for(int i = 16; i < 64; i ++) W[i] = ((((((W[i - 2] & 0xffffffff) >> 17) | (W[i - 2] << 15)) & 0xffffffff) ^ ((((W[i - 2] & 0xffffffff) >> 19) | (W[i - 2] << 13)) & 0xffffffff) ^ ((W[i - 2] & 0xffffffff) >> 10)) + W[i - 7] + (((((W[i - 15] & 0xffffffff) >> 7) | (W[i - 15] << 25)) & 0xffffffff) ^ ((((W[i - 15] & 0xffffffff) >> 18) | (W[i - 15] << 14)) & 0xffffffff) ^ ((W[i - 15] & 0xffffffff) >> 3)) + W[i - 16]) & 0xffffffff;
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0x428a2f98, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0x71374491, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0xb5c0fbcf, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0xe9b5dba5, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x3956c25b, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0x59f111f1, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x923f82a4, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0xab1c5ed5, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0xd807aa98, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0x12835b01, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0x243185be, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0x550c7dc3, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x72be5d74, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0x80deb1fe, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x9bdc06a7, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0xc19bf174, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0xe49b69c1, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0xefbe4786, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0x0fc19dc6, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0x240ca1cc, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x2de92c6f, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0x4a7484aa, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x5cb0a9dc, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0x76f988da, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0x983e5152, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0xa831c66d, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0xb00327c8, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0xbf597fc7, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0xc6e00bf3, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0xd5a79147, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x06ca6351, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0x14292967, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0x27b70a85, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0x2e1b2138, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0x4d2c6dfc, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0x53380d13, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x650a7354, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0x766a0abb, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x81c2c92e, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0x92722c85, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0xa2bfe8a1, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0xa81a664b, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0xc24b8b70, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0xc76c51a3, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0xd192e819, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0xd6990624, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0xf40e3585, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0x106aa070, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0x19a4c116, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0x1e376c08, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0x2748774c, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0x34b0bcb5, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x391c0cb3, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0x4ed8aa4a, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0x5b9cca4f, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0x682e6ff3, W);
    RND(ss[0], ss[1], ss[2], ss + 3, ss[4], ss[5], ss[6], ss + 7, 0x748f82ee, W);
    RND(ss[7], ss[0], ss[1], ss + 2, ss[3], ss[4], ss[5], ss + 6, 0x78a5636f, W);
    RND(ss[6], ss[7], ss[0], ss + 1, ss[2], ss[3], ss[4], ss + 5, 0x84c87814, W);
    RND(ss[5], ss[6], ss[7], ss + 0, ss[1], ss[2], ss[3], ss + 4, 0x8cc70208, W);
    RND(ss[4], ss[5], ss[6], ss + 7, ss[0], ss[1], ss[2], ss + 3, 0x90befffa, W);
    RND(ss[3], ss[4], ss[5], ss + 6, ss[7], ss[0], ss[1], ss + 2, 0xa4506ceb, W);
    RND(ss[2], ss[3], ss[4], ss + 5, ss[6], ss[7], ss[0], ss + 1, 0xbef9a3f7, W);
    RND(ss[1], ss[2], ss[3], ss + 4, ss[5], ss[6], ss[7], ss + 0, 0xc67178f2, W);
    for(int i = 0; i < 8; i ++) _sha -> digest[i] = (_sha -> digest[i] + ss[i]) & 0xffffffff;
}
int atoi(char *str) {
    int output = 0;
    for (int i = 0; str[i] != '\0'; ++ i) output = output * 10 + str[i] - '0';
    return output;
}
int strcmp(const char *p1, const char *p2) {
    const unsigned char *s1 = (const unsigned char *) p1;
    const unsigned char *s2 = (const unsigned char *) p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char) *s1 ++;
        c2 = (unsigned char) *s2 ++;
        if (c1 == '\0') return c1 - c2;
    } while (c1 == c2);
    return c1 - c2;
}
unsigned long strlen(const char *str) {
    const char *char_ptr;
    const unsigned long int *longword_ptr;
    unsigned long int longword, himagic, lomagic;
    for(char_ptr = str; ((unsigned long int) char_ptr & (sizeof (longword) - 1)) != 0; ++ char_ptr) if (*char_ptr == '\0') return char_ptr - str;
    longword_ptr = (unsigned long int *) char_ptr;
    himagic = 0x80808080L;
    lomagic = 0x01010101L;
    if(sizeof(longword) > 4) {
        himagic = ((himagic << 16) << 16) | himagic;
        lomagic = ((lomagic << 16) << 16) | lomagic;
    }
    while(1) {
        longword = *longword_ptr ++;
        if (((longword - lomagic) & ~longword & himagic) != 0) {
            const char *cp = (const char *) (longword_ptr - 1);
            if(cp[0] == 0) return cp - str;
            if(cp[1] == 0) return cp - str + 1;
            if(cp[2] == 0) return cp - str + 2;
            if(cp[3] == 0) return cp - str + 3;
            if(sizeof(longword) > 4) {
                if(cp[4] == 0) return cp - str + 4;
                if(cp[5] == 0) return cp - str + 5;
                if(cp[6] == 0) return cp - str + 6;
                if(cp[7] == 0) return cp - str + 7;
            }
        }
    }
}
void update(SHA *_sha, char *buffer){ //ToDo: Add support for non-ascii characters
    int count = strlen(buffer);
    int index = 0;
    int clo = (_sha -> lo + (count << 3)) & 0xffffffff;
    if(clo < _sha -> lo) _sha -> hi ++;
    _sha -> lo = clo;
    _sha -> hi += (count >> 29);
    if(_sha -> local){
        int i = 64 - _sha -> local;
        if(i > count) i = count;
        for(int j = 0; j < i; j ++) _sha -> data[_sha -> local + j] = (int) buffer[index + j];
        count -= i;
        index += i;
        _sha -> local += i;
        if(_sha -> local == 64){
            transform(_sha);
            _sha -> local = 0;
        } else {return;}
    }
    while(count >= 64){
        for(int i = 0; i < 64; i ++) _sha -> data[i] = (int) buffer[index + i];
        count -= 64;
        index += 64;
        transform(_sha);
    }
    int pos = _sha -> local;
    for(int i = pos; i < pos + count; i ++) _sha -> data[i] = (int) buffer[index + i];
    _sha -> local = count;
}
char *digest(char *s) {
    static char returnValue[33];
    SHA _sha = sha256;
    if(s[0] != '\0') update(&_sha, s);
    int lo_bit_count = _sha.lo;
    int hi_bit_count = _sha.hi;
    int count = (lo_bit_count >> 3) & 0x3f;
    _sha.data[count ++] = 0x80;
    if(count > 56){
        transform(&_sha);
        for(int i = 0; i < 64; i ++) _sha.data[i] = 0;
    }
    _sha.data[56] = (hi_bit_count >> 24) & 0xff;
    _sha.data[57] = (hi_bit_count >> 16) & 0xff;
    _sha.data[58] = (hi_bit_count >> 8) & 0xff;
    _sha.data[59] = (hi_bit_count) & 0xff;
    _sha.data[60] = (lo_bit_count >> 24) & 0xff;
    _sha.data[61] = (lo_bit_count >> 16) & 0xff;
    _sha.data[62] = (lo_bit_count >> 8) & 0xff;
    _sha.data[63] = (lo_bit_count) & 0xff;
    transform(&_sha);
    for(int i = 0; i <= 7;) {
        for(int j = 24; j >= 0; j -= 8) sprintf(returnValue, "%s%c", returnValue, (int)(_sha.digest[i] >> j) & 0xff);
        i++;
    }
    return returnValue;
}
char *hexdigest(char *s) {
    static char returnValue[65];
    SHA _sha = sha256;
    if(s[0] != '\0') update(&_sha, s);
    int lo_bit_count = _sha.lo;
    int hi_bit_count = _sha.hi;
    int count = (lo_bit_count >> 3) & 0x3f;
    _sha.data[count ++] = 0x80;
    if(count > 56){
        transform(&_sha);
        for(int i = 0; i < 64; i ++) _sha.data[i] = 0;
    }
    _sha.data[56] = (hi_bit_count >> 24) & 0xff;
    _sha.data[57] = (hi_bit_count >> 16) & 0xff;
    _sha.data[58] = (hi_bit_count >> 8) & 0xff;
    _sha.data[59] = (hi_bit_count) & 0xff;
    _sha.data[60] = (lo_bit_count >> 24) & 0xff;
    _sha.data[61] = (lo_bit_count >> 16) & 0xff;
    _sha.data[62] = (lo_bit_count >> 8) & 0xff;
    _sha.data[63] = (lo_bit_count) & 0xff;
    transform(&_sha);
    for(int i = 7; i >= 0;) {
        for(int j = 0; j <= 24;j += 8) sprintf(returnValue, "%s%.2lx", returnValue, (_sha.digest[i] >> j) & 0xff);
        i--;
    }
    return returnValue;
}
int a2v(char c) {
    if ((c >= '0') && (c <= '9')) return c - '0';
    else return c - 'a' + 10;
}
char *SwapL(char s[64]){
    static char o[65];
    for(int i = 0; i < 64; i += 2){
        o[i] = s[62 - i];
        o[i + 1] = s[63 - i];
    }
    return o;
}
char *process(int bits, int version, char *lastHash, char *merkleRoot){
    char hexBits[9];
    char blockData[161];
    char blockData1[161];
    char target[65];
    char hexVersion[9];
    char hexBits1[9];
    char hash[65];
    static char hashData[161];
    char hashData1[81];
    unsigned long nonce;
    sprintf(hexBits, "%.8x", Swap(bits));
    sprintf(target, "%x", bits & 0xffffff);
    for(int p = 0; p < ((bits >> 24 << 1) - 6); p ++) sprintf(target, "%s0", target);
    while(strlen(target) < 64) sprintf(target, "0%s", target);
    sprintf(hexVersion, "%.8x", Swap(version));
    sprintf(blockData1, "%s%s%s", hexVersion, SwapL(lastHash), SwapL(merkleRoot));
    while(1) {
        nonce = 0;
        sprintf(blockData, "%s%.8lx%s", blockData1, Swap(time()), hexBits);
        do {
            if(nonce >= 1 << 24) sprintf(hashData, "%s%.8lx", blockData, Swap(nonce));
            else if(nonce >= 1 << 16) sprintf(hashData, "%s%.6lx", blockData, ((nonce >> 16) & 0xff) | (nonce & 0xff00) | ((nonce << 16) & 0xff0000));
            else if(nonce >= 1 << 8) sprintf(hashData, "%s%.4lx", blockData, ((nonce >> 8) & 0xff) | ((nonce << 8) & 0xff00));
            else sprintf(hashData, "%s%.2lx", blockData, nonce);
            for (int i = 0; i < strlen(hashData); i += 2) hashData1[i/2] = (a2v(hashData[i]) << 4) + a2v(hashData[i + 1]);
            sprintf(hash, "%s", hexdigest(digest(hashData1))); //ToDo: Write as one function
            if(strcmp(hash, target) <= 0) return hashData;
        } while(nonce ++ != 0xffffffffUL);
    }
}
int main(int argc, char *argv[]) {
    if(argc != 5) {
        printf("Wrong number of arguments!");
        return 1;
    }
    puts(process(atoi(argv[1]), atoi(argv[2]), argv[3], argv[4]));
    return 0;
}
