import bearssl, strutils
from os import DirSep

const
  bearPath = currentSourcePath.rsplit(DirSep, 1)[0] & DirSep &
             "bearssl_pkey_decoder" & DirSep & "csources"

{.compile(bearPath & DirSep & "bearssl_pkey_decoder.c", "-I" & bearPath).}

# This pragma should be the same as in nim-bearssl/decls.nim
{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

type
  INNER_C_UNION_KEY* {.union.} = object
    rsa*: RsaPublicKey
    ec*: EcPublicKey

  INNER_C_STRUCT_CPU* = object
    dp*: ptr uint32
    rp*: ptr uint32
    ip*: ptr cuchar

  PkeyDecoderContext* = object
    key*: INNER_C_UNION_KEY
    cpu*: INNER_C_STRUCT_CPU
    dpStack*: array[32, uint32]
    rpStack*: array[32, uint32]
    err*: cint
    hbuf*: pointer
    hlen*: csize_t
    pad*: array[256, byte]
    key_type*: uint8
    key_data*: array[3 * X509_BUFSIZE_SIG, byte]

proc pkeyDecoderInit*(ctx: ptr PkeyDecoderContext) {.bearSslFunc,
    importc: "br_pkey_decoder_init".}

proc pkeyDecoderPush*(ctx: ptr PkeyDecoderContext; data: pointer; len: csize_t) {.bearSslFunc,
    importc: "br_pkey_decoder_push".}

proc pkeyDecoderLastError*(ctx: ptr PkeyDecoderContext): cint =
  if ctx.err != 0:
    return ctx.err
  if ctx.key_type == 0:
    return ERR_X509_TRUNCATED

proc pkeyDecoderKeyType*(ctx: ptr PkeyDecoderContext): cint =
  if ctx.err == 0:
    return cast[cint](ctx.key_type)
  0

proc pkeyDecoderGetRsa*(ctx: ptr PkeyDecoderContext): ptr RsaPublicKey =
  if ctx.err == 0 and ctx.key_type == KEYTYPE_RSA:
    return addr ctx.key.rsa

proc pkeyDecoderGetEc*(ctx: ptr PkeyDecoderContext): ptr EcPublicKey =
  if ctx.err == 0 and ctx.key_type == KEYTYPE_EC:
    return addr ctx.key.ec
