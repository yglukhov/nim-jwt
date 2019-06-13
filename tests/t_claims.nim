import json, unittest

import ../jwt

suite "Claim ops":
  test "Create claims from JSON":
    let asJson = %{
      "iss": %"jane",
      "sub": %"john",
      "nbf": %1234,
      "iat": %1234,
      "exp": %1234,
      "jti": %"token-id",
      "foo": %{"bar": %1}
    }
    let claims = asJson.toClaims
    let toJson = %claims

    assert asJson.len == toJson.len
    for k, v in asJson:
      assert v == toJson[k]
