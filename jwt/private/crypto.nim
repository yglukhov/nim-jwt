import bearssl, bearssl_pkey_decoder

# This pragma should be the same as in nim-bearssl/decls.nim
{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

proc bearHMAC*(digestVtable: ptr HashClass; key, d: string): seq[byte] =
  var hKey: HmacKeyContext
  var hCtx: HmacContext
  hmacKeyInit(hKey, digestVtable, key.cstring, key.len.csize_t)
  hmacInit(hCtx, hKey, 0)
  hmacUpdate(hCtx, d.cstring, d.len.csize_t)
  let sz = hmacSize(hCtx)
  result = newSeqUninit[byte](sz)
  discard hmacOut(hCtx, addr result[0])

proc invalidPemKey() =
  raise newException(ValueError, "Invalid PEM encoding")

proc pemDecoderLoop(pem: string, prc: proc(ctx: pointer, pbytes: pointer, nbytes: csize_t) {.bearSslFunc.}, ctx: pointer) =
  var pemCtx: PemDecoderContext
  pemDecoderInit(pemCtx)
  var length = len(pem)
  var offset = 0
  var inobj = false
  while length > 0:
    var tlen = pemDecoderPush(pemCtx,
                              unsafeAddr pem[offset], length.csize_t).int
    offset = offset + tlen
    length = length - tlen

    let event = pemDecoderEvent(pemCtx)
    if event == PEM_BEGIN_OBJ:
      inobj = true
      pemDecoderSetdest(pemCtx, prc, ctx)
    elif event == PEM_END_OBJ:
      if inobj:
        inobj = false
      else:
        break
    elif event == 0 and length == 0:
      break
    else:
      invalidPemKey()

proc decodeFromPem(skCtx: var SkeyDecoderContext, pem: string) =
  skeyDecoderInit(skCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: csize_t) {.bearSslFunc.}](skeyDecoderPush), addr skCtx)
  if skeyDecoderLastError(skCtx) != 0: invalidPemKey()

proc decodeFromPem(pkCtx: var PkeyDecoderContext, pem: string) =
  pkeyDecoderInit(addr pkCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: csize_t) {.bearSslFunc.}](pkeyDecoderPush), addr pkCtx)
  if pkeyDecoderLastError(addr pkCtx) != 0: invalidPemKey()

proc calcHash(alg: ptr HashClass, data: string, output: var array[64, byte]) =
  var ctx: array[512, byte]
  let pCtx = cast[ptr ptr HashClass](addr ctx[0])
  assert(alg.contextSize <= sizeof(ctx).uint)
  alg.init(pCtx)
  if data.len > 0:
    alg.update(pCtx, unsafeAddr data[0], data.len.csize_t)
  alg.`out`(pCtx, addr output[0])

proc bearSignRSPem*(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  # Step 1. Extract RSA key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_RSA:
    invalidPemKey()

  template pk(): RsaPrivateKey = skCtx.key.rsa

  # Step 2. Hash!
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let sigLen = (pk.nBitlen + 7) div 8
  result = newSeqUninit[byte](sigLen)
  let s = rsaPkcs1SignGetDefault()
  assert(not s.isNil)
  if s(cast[ptr byte](hashOid), addr digest[0], hashLen.csize_t, addr pk, addr result[0]) != 1:
    raise newException(ValueError, "Could not sign")

proc bearVerifyRSPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashOid: cstring, hashLen: int): bool =
  # Step 1. Extract RSA key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_RSA:
    invalidPemKey()
  template pk(): RsaPublicKey = pkCtx.key.rsa

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let s = rsaPkcs1VrfyGetDefault()
  var digest2: array[64, byte]

  if s(unsafeAddr sig[0], sig.len.csize_t, cast[ptr byte](hashOid), hashLen.csize_t, addr pk, addr digest2[0]) != 1:
    return false

  digest == digest2

proc bearSignECPem*(data, key: string, alg: ptr HashClass): seq[byte] =
  # Step 1. Extract EC Priv key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_EC:
    invalidPemKey()

  template pk(): EcPrivateKey = skCtx.key.ec

  # Step 2. Hash!
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  const maxSigLen = 140 # according to bearssl doc

  result = newSeqUninit[byte](maxSigLen)
  let s = ecdsaSignRawGetDefault()
  assert(not s.isNil)
  let impl = ecGetDefault()
  let sz = s(impl, alg, addr digest[0], addr pk, cast[ptr char](addr result[0]))
  assert(sz <= maxSigLen)
  result.setLen(sz)

proc bearVerifyECPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashLen: int): bool =
  # Step 1. Extract EC Pub key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_EC:
    invalidPemKey()
  template pk(): EcPublicKey = pkCtx.key.ec

  # bearssl ecdsaVrfy requires pubkey to be prepended with 0x04 byte, do it here
  assert((pk.q == addr pkCtx.key_data) and pk.qlen < sizeof(pkCtx.key_data).uint)
  moveMem(addr pkCtx.key_data[1], addr pkCtx.key_data[0], pk.qlen)
  pkCtx.key_data[0] = 0x04
  inc pk.qlen

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let impl = ecGetDefault()
  let s = ecdsaVrfyRawGetDefault()
  result = s(impl, addr digest[0], hashLen.csize_t, addr pk, unsafeAddr sig[0], sig.len.csize_t) == 1
