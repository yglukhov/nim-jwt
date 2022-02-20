import json, strutils

import utils

type
  UnsupportedAlgorithm* = object of ValueError

  SignatureAlgorithm* = enum
    NONE
    HS256
    HS384
    HS512
    RS256
    RS384
    RS512
    ES256
    ES384
    ES512

proc strToSignatureAlgorithm(s: string): SignatureAlgorithm =
  try:
    result = parseEnum[SignatureAlgorithm](s)
  except ValueError:
    raise newException(UnsupportedAlgorithm, "$# isn't supported" % s)


proc toHeader*(j: JsonNode): JsonNode =
  # Check that the keys are present so we dont blow up.
  result = newJObject()
  utils.checkKeysExists(j, "alg", "typ")
  # we do this attribute by attribute because some tests depend on the order of these keys
  result["alg"] = %strToSignatureAlgorithm(j["alg"].getStr())
  result["typ"] = j["typ"]
  for key in j.keys:
    if not result.hasKey(key):
      result[key] = j[key]

proc alg*(j: JsonNode): SignatureAlgorithm =
  doAssert j.hasKey("alg")
  return j["alg"].getStr().strToSignatureAlgorithm()

proc `%`*(alg: SignatureAlgorithm): JsonNode =
  let s = $alg
  return %s


proc toBase64*(h: JsonNode): string =
  result = encodeUrlSafe($h)
