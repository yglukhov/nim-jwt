import bearssl, bearssl_pkey_decoder

proc bearHMAC*(digestVtable: ptr HashClass; key, d: string): seq[byte] =
  var hKey: HmacKeyContext
  var hCtx: HmacContext
  hmacKeyInit(addr hKey, digestVtable, key.cstring, key.len)
  hmacInit(addr hCtx, addr hKey, 0)
  hmacUpdate(addr hCtx, d.cstring, d.len)
  let sz = hmacSize(addr hCtx)
  result = newSeqUninitialized[byte](sz)
  discard hmacOut(addr hCtx, addr result[0])

proc invalidPemKey() =
  raise newException(Exception, "Invalid PEM encoding")

proc pemDecoderLoop(pem: string, prc: proc(ctx: pointer, pbytes: pointer, nbytes: int) {.cdecl, gcsafe.}, ctx: pointer) =
  var pemCtx: PemDecoderContext
  pemDecoderInit(addr pemCtx)
  var length = len(pem)
  var offset = 0
  var inobj = false
  while length > 0:
    var tlen = pemDecoderPush(addr pemCtx,
                              unsafeAddr pem[offset], length)
    offset = offset + tlen
    length = length - tlen

    let event = pemDecoderEvent(addr pemCtx)
    if event == PEM_BEGIN_OBJ:
      inobj = true
      pemDecoderSetdest(addr pemCtx, prc, ctx)
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
  skeyDecoderInit(addr skCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: int) {.cdecl, gcsafe.}](skeyDecoderPush), addr skCtx)
  if skeyDecoderLastError(addr skCtx) != 0: invalidPemKey()

proc decodeFromPem(pkCtx: var PkeyDecoderContext, pem: string) =
  pkeyDecoderInit(addr pkCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: int) {.cdecl, gcsafe.}](pkeyDecoderPush), addr pkCtx)
  if pkeyDecoderLastError(addr pkCtx) != 0: invalidPemKey()

proc calcHash(alg: ptr HashClass, data: string, output: var array[64, byte]) =
  var ctx: array[512, byte]
  let pCtx = cast[ptr ptr HashClass](addr ctx[0])
  assert(alg.contextSize <= sizeof(ctx))
  alg.init(pCtx)
  if data.len > 0:
    alg.update(pCtx, unsafeAddr data[0], data.len)
  alg.output(pCtx, addr output[0])

proc bearSignRSPem*(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  # Step 1. Extract RSA key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(addr skCtx) != KEYTYPE_RSA:
    invalidPemKey()

  template pk(): RsaPrivateKey = skCtx.key.rsa

  # Step 2. Hash!
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let sigLen = (pk.nBitlen + 7) div 8
  result = newSeqUninitialized[byte](sigLen)
  let s = rsaPkcs1SignGetDefault()
  assert(not s.isNil)
  if s(cast[ptr cuchar](hashOid), cast[ptr cuchar](addr digest[0]), hashLen, addr pk, cast[ptr cuchar](addr result[0])) != 1:
    raise newException(Exception, "Could not sign")

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

  if s(cast[ptr cuchar](unsafeAddr sig[0]), sig.len, cast[ptr cuchar](hashOid), hashLen, addr pk, cast[ptr cuchar](addr digest2[0])) != 1:
    raise newException(Exception, "Could not verify")

  digest == digest2

# const ecPublicKey = """-----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
# q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
# -----END PUBLIC KEY-----"""

# var EC_P256_PUB_POINT = @[
#   0x04.uint8, 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D,
#   0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D,
#   0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA,
#   0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F,
#   0xB6, 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC,
#   0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC,
#   0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F,
#   0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22,
#   0x99
# ]

# var EC_P256_PRIV_X = @[
#   0xC9.uint8, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
#   0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
#   0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
#   0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
# ]


proc bearSignECPem*(data, key: string, alg: ptr HashClass, impl: ptr EcImpl): seq[byte] =
  # Step 1. Extract RSA key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(addr skCtx) != KEYTYPE_EC:
    invalidPemKey()

  template pk(): EcPrivateKey = skCtx.key.ec
  # var pk: EcPrivateKey
  # pk.curve = 23
  # pk.x = cast[ptr cuchar](addr EC_P256_PRIV_X[0])
  # pk.xlen = EC_P256_PRIV_X.len

  # Step 2. Hash!
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  const maxSigLen = 140 # according to bearssl doc

  result = newSeqUninitialized[byte](maxSigLen)
  let s = ecdsaSignRawGetDefault()
  assert(not s.isNil)
  let sz = s(impl, alg, addr digest[0], addr pk, cast[ptr cuchar](addr result[0]))
  assert(sz <= maxSigLen)
  result.setLen(sz)

  # if ecPublicKey != "":
  #   var pkCtx: PkeyDecoderContext
  #   decodeFromPem(pkCtx, ecPublicKey)
  #   if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_EC:
  #     invalidPemKey()
  #   template puk(): EcPublicKey = pkCtx.key.ec
  #   # var puk: EcPublicKey
  #   # puk.curve = 23
  #   # puk.q = cast[ptr cuchar](addr EC_P256_PUB_POINT[0])
  #   # puk.qlen = EC_P256_PUB_POINT.len
  
  
  #   let v = ecdsaVrfyRawGetDefault()
  #   # echo "hs: ", hashLen
  #   # echo "vrfy digest: ", digest.toHex
  #   let r = v(impl, cast[ptr cuchar](addr digest[0]), 32, addr puk, cast[ptr cuchar](unsafeAddr result[0]), result.len)
  #   echo "Verify after sign: ", r

  # echo "len: ", result.toHex

proc bearVerifyECPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, impl: ptr EcImpl, hashLen: int): bool =
  # Step 1. Extract RSA key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_EC:
    invalidPemKey()
  template pk(): EcPublicKey = pkCtx.key.ec

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let s = ecdsaVrfyRawGetDefault()
  result = s(impl, cast[ptr cuchar](addr digest[0]), hashLen, addr pk, cast[ptr cuchar](unsafeAddr sig[0]), sig.len) == 1
