import openssl, linktools

# TODO: Linkage flags should probably need more attention because of different
# openssl versions. E.g. DigestSign* functions are not available in old openssl.
when defined(macosx):
  const libcrypto = "crypto"
else:
  const libcrypto = "crypto"

{.passL: "-l" & libcrypto.}

export EVP_PKEY_RSA

const
  HMAC_MAX_MD_CBLOCK* = 128

const sslIsOld = true #libHasSymbol(libcrypto, "EVP_MD_CTX_create")

type
  EVP_MD* = SslPtr
  EVP_MD_CTX* = SslPtr
  EVP_PKEY_CTX* = SslPtr
  ENGINE* = SslPtr

proc EVP_md_null*(): EVP_MD   {.cdecl, importc.}
proc EVP_md2*(): EVP_MD       {.cdecl, importc.}
proc EVP_md4*(): EVP_MD       {.cdecl, importc.}
proc EVP_md5*(): EVP_MD       {.cdecl, importc.}
proc EVP_sha*(): EVP_MD       {.cdecl, importc.}
proc EVP_sha1*(): EVP_MD      {.cdecl, importc.}
proc EVP_dss*(): EVP_MD       {.cdecl, importc.}
proc EVP_dss1*(): EVP_MD      {.cdecl, importc.}
proc EVP_ecdsa*(): EVP_MD     {.cdecl, importc.}
proc EVP_sha224*(): EVP_MD    {.cdecl, importc.}
proc EVP_sha256*(): EVP_MD    {.cdecl, importc.}
proc EVP_sha384*(): EVP_MD    {.cdecl, importc.}
proc EVP_sha512*(): EVP_MD    {.cdecl, importc.}
proc EVP_mdc2*(): EVP_MD      {.cdecl, importc.}
proc EVP_ripemd160*(): EVP_MD {.cdecl, importc.}
proc EVP_whirlpool*(): EVP_MD {.cdecl, importc.}

proc HMAC*(evp_md: EVP_MD; key: pointer; key_len: cint; d: cstring;
           n: csize; md: cstring; md_len: ptr cuint): cstring {.cdecl, importc.}

proc PEM_read_bio_PrivateKey*(bp: BIO, x: ptr EVP_PKEY,
            cb: pointer, u: pointer): EVP_PKEY {.cdecl, importc.}
proc EVP_PKEY_free*(p: EVP_PKEY)  {.cdecl, importc.}

when sslIsOld:
  proc EVP_MD_CTX_create*(): EVP_MD_CTX {.cdecl, importc.}
  proc EVP_MD_CTX_destroy*(ctx: EVP_MD_CTX) {.cdecl, importc.}
else:
  proc EVP_MD_CTX_create*(): EVP_MD_CTX {.cdecl, importc: "EVP_MD_CTX_new".}
  proc EVP_MD_CTX_destroy*(ctx: EVP_MD_CTX) {.cdecl, importc: "EVP_MD_CTX_free".}

proc EVP_DigestSignInit*(ctx: EVP_MD_CTX, pctx: ptr EVP_PKEY_CTX,
            typ: EVP_MD, e: ENGINE, pkey: EVP_PKEY): cint {.cdecl, importc.}

proc EVP_DigestSignUpdate*(ctx: EVP_MD_CTX, data: pointer, len: cuint): cint {.cdecl, importc: "EVP_DigestUpdate".}
proc EVP_DigestSignFinal*(ctx: EVP_MD_CTX, data: pointer, len: ptr csize): cint {.cdecl, importc.}

proc EVP_PKEY_CTX_new*(pkey: EVP_PKEY, e: ENGINE): EVP_PKEY_CTX {.cdecl, importc.}
proc EVP_PKEY_sign_init*(c: EVP_PKEY_CTX): cint {.cdecl, importc.}

when not declared(BIO_new_mem_buf):
  proc BIO_new_mem_buf*(data: pointer, len: cint): BIO{.cdecl, importc.}

proc signPem*(data, key: string, alg: EVP_MD, typ: cint): seq[uint8] =
  var bufkey: BIO
  var pkey: EVP_PKEY
  var mdctx: EVP_MD_CTX

  defer:
    if not bufkey.isNil: discard BIO_free(bufkey)
    if not pkey.isNil: EVP_PKEY_free(pkey)
    if not mdctx.isNil: EVP_MD_CTX_destroy(mdctx)

  bufkey = BIO_new_mem_buf(unsafeAddr key[0], cint(key.len))
  if bufkey.isNil:
    raise newException(Exception, "Out of memory")
  pkey = PEM_read_bio_PrivateKey(bufkey, nil, nil, nil)
  if pkey.isNil:
    raise newException(Exception, "Invalid value")
  mdctx = EVP_MD_CTX_create()
  if mdctx.isNil:
    raise newException(Exception, "Out of memory")

  let pkeyCtx = EVP_PKEY_CTX_new(pkey, nil)
  if EVP_PKEY_sign_init(pkeyCtx) <= 0:
    raise newException(Exception, "Invalid value")

  # Initialize the DigestSign operation using alg
  if EVP_DigestSignInit(mdctx, nil, alg, nil, pkey) != 1:
    raise newException(Exception, "Invalid value")

  # Call update with the message
  if EVP_DigestSignUpdate(mdctx, unsafeAddr data[0], cuint(data.len)) != 1:
    raise newException(Exception, "Invalid value")

  # First, call EVP_DigestSignFinal with a NULL sig parameter to get length
  # of sig. Length is returned in slen
  var slen: csize
  if EVP_DigestSignFinal(mdctx, nil, addr slen) != 1:
    raise newException(Exception, "Invalid value")

  # Allocate memory for signature based on returned size
  result = newSeq[uint8](slen)

  # Get the signature
  if EVP_DigestSignFinal(mdctx, addr result[0], addr slen) != 1:
    raise newException(Exception, "Invalid value")
