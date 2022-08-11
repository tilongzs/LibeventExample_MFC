#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int _b64idx(int c)
{
  if (c < 26)
  {
    return c + 'A';
  }
  else if (c < 52)
  {
    return c - 26 + 'a';
  }
  else if (c < 62)
  {
    return c - 52 + '0';
  }
  else
  {
    return c == 62 ? '+' : '/';
  }
}

static int _b64rev(int c)
{
  if (c >= 'A' && c <= 'Z')
  {
    return c - 'A';
  }
  else if (c >= 'a' && c <= 'z')
  {
    return c + 26 - 'a';
  }
  else if (c >= '0' && c <= '9')
  {
    return c + 52 - '0';
  }
  else if (c == '+')
  {
    return 62;
  }
  else if (c == '/')
  {
    return 63;
  }
  else if (c == '=')
  {
    return 64;
  }
  else
  {
    return -1;
  }
}

static int _base64_update(unsigned char ch, char *to, int n)
{
  int rem = (n & 3) % 3;
  if (rem == 0)
  {
    to[n] = (char) _b64idx(ch >> 2);
    to[++n] = (char) ((ch & 3) << 4);
  }
  else if (rem == 1)
  {
    to[n] = (char) _b64idx(to[n] | (ch >> 4));
    to[++n] = (char) ((ch & 15) << 2);
  }
  else
  {
    to[n] = (char) _b64idx(to[n] | (ch >> 6));
    to[++n] = (char) _b64idx(ch & 63);
    n++;
  }
  return n;
}

static int _base64_final(char *to, int n)
{
  int saved = n;
  if(to==NULL)
    return 0;
  if (n & 3) n = _base64_update(0, to, n);
  if ((saved & 3) == 2)
    n--;
  while (n & 3)
    to[n++] = '=';
  to[n] = '\0';
  return n;
}

int base64_encode(const unsigned char *p, int n, char *to)
{
  int i, len = 0;
  if(p==NULL)
    return 0;
  if(to==NULL)
    return 0;
  for (i = 0; i < n; i++)
    len = _base64_update(p[i], to, len);
  len = _base64_final(to, len);
  return len;
}

int base64_decode(const char *src, int n, char *dst)
{
  const char *end = src + n;
  int len = 0;
  if(src==NULL)
    return 0;
  if(dst==NULL)
    return 0;
  while (src + 3 < end)
  {
    int a = _b64rev(src[0]), b = _b64rev(src[1]), c = _b64rev(src[2]),
        d = _b64rev(src[3]);
    if (a == 64 || a < 0 || b == 64 || b < 0 || c < 0 || d < 0) return 0;
    dst[len++] = (char) ((a << 2) | (b >> 4));
    if (src[2] != '=') {
      dst[len++] = (char) ((b << 4) | (c >> 2));
      if (src[3] != '=') dst[len++] = (char) ((c << 6) | d);
    }
    src += 4;
  }
  dst[len] = '\0';
  return len;
}
