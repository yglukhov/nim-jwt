import json, strutils

from base64 import nil


type
  KeyError = object of Exception

proc checkJsonNodeKind*(node: JsonNode, kind: JsonNodeKind) =
  # Check that a given JsonNode has a given kind, raise InvalidClaim if not
  if node.kind != kind:
    raise newException(ValueError, "Invalid kind")


proc checkKeysExists*(node: JsonNode, keys: varargs[string]) =
  for key in keys:
    if not node.hasKey(key):
      raise newException(KeyError, "$# is not present." % key)


proc encodeUrlSafe*(s: string): string =
  result = base64.encode(s, newLine="")
  while result.endsWith("="):
    result = result.substr(0, result.high-1)
    result = result.replace('+', '-').replace('/', '_')


proc decodeUrlSafe*(s: string): string =
  var s = s
  while s.len mod 4 > 0:
    s &= "="
  base64.decode(s).replace('+', '-').replace('/', '_')