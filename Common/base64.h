#ifndef _BASE64_H_
#define _BASE64_H_

#ifdef __cplusplus
extern "C"{
#endif

int base64_encode(const unsigned char *p, int n, char *to);
int base64_decode(const char *src, int n, char *dst);

#ifdef __cplusplus
}
#endif

#endif // _BASE64_H_
