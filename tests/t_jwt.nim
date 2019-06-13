import json, times, unittest
from times import nil

import ../jwt

proc getToken(claims: JsonNode = newJObject(), header: JsonNode = newJObject()): JWT =
  let claims = claims.toClaims

  for k, v in %{"alg": %"HS256", "typ": %"JWT"}:
    if not header.hasKey(k):
      header[k] = v

  let headers = header.toHeader

  result = JWT(
    claims: claims,
    header: headers
  )

suite "Token tests":
  test "Load from JSON and verify":
    # Load a token from json
    var
      token = getToken()
      secret = "secret"

    token.sign(secret)

    let b64Token = $token
    token = b64Token.toJWT
    assert token.verify(secret) == true

  test "NBF Check":
    let
      now = getTime().toUnix.int + 60
      token = getToken(claims = %{"nbf": %now})
    expect(InvalidToken):
      token.verifyTimeClaims

  test "EXP Check":
    let
      now = getTime().toUnix.int - 60
      token = getToken(claims = %{"exp": %now})
    expect(InvalidToken):
      token.verifyTimeClaims
