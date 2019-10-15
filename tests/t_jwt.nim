import json, times, unittest

import ../jwt

proc getToken(claims: JsonNode = newJObject(), header: JsonNode = newJObject()): JWT =
  for k, v in %*{"alg": "HS512", "typ": "JWT"}:
    if not header.hasKey(k):
      header[k] = v

  initJWT(header.toHeader, claims.toClaims)

proc tokenWithAlg(alg: string): JWT =
  let header = %*{ "typ": "JWT", "alg": alg }
  let claims = %*{ "sub": "1234567890",
                   "name": "John Doe",
                   "iat": 1516239022 }
  initJWT(header.toHeader, claims.toClaims)

proc signedHSToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign("your-256-secret")

const
  rsPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----"""
  rsPublicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----"""
  ecPrivateKey = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"""
  ecPublicKey = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"""

proc signedRSToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(rsPrivateKey)

proc signedECToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(ecPrivateKey)

suite "Token tests":
  test "Load from JSON and verify":
    # Load a token from json
    var
      token = getToken()
      secret = "secret"

    token.sign(secret)

    let b64Token = $token
    token = b64Token.toJWT
    check token.verify(secret) == true

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

  test "HS Signature":
    # Checked with https://jwt.io/
    check:
      $signedHSToken("HS256") == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.sBnEuqpBDTh4Q9wnxfhWKHPbbspoz-qPNxXqVSS7ZYE"
      $signedHSToken("HS384") == "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.e-lF0-wO2pi5y5fCOHPFLTuHqm2hR1LIX3gaCz0xI_Nvw-KPNIpkKVcbxWl2pPz8"
      $signedHSToken("HS512") == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.oAFx4658Y0Bbjko7Vm-X1AUd4XRjvnuznZk8cihzDuIRSZQjXnveoKuj8PIkAWviz-5c--R1HSyM6HZuONtrLQ"

  test "RS Signature":
    # Checked with https://jwt.io/
    check:
      $signedRSToken("RS256") == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.O2LIRo2GPEVHQCG3nHGvvY89__LgKLPo9EYXLDzH3oQnh_hZvlk350htpqaNMowOlxYGdM77oLsdHVxzFdto9c1pCH0jBG-HXzIKm131QxsZzCyO8ovW_2i6PGeNvsiaggrkdmOKcWcyMksasJcuqIf0h_fWhiK4wdq41Ls8ujLJpQBF3XNzOPt90so7XEvkY0zDVS0N3Bi6Hz5cN101FJFyMcDnq_3QSGMWPy829vC8PT8C0WCBIs7VdK9tEwIvpDENhRRj6cxhUqLCC0ALoynZYBeMcvOWQcz-LqbWuQGvuH2HGsN9zCpbaTdkiupNX__DKG0HUijnesYn1DkY2g"
      $signedRSToken("RS384") == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.OGwjm7YvGCh4gpIuFnM7K88_dEeiSAWzpR0dXzhsne1IPygnXRKoTCdmhA2a01Mj_cW6tWhufSGcuu-7vmdm5Hi8hoDe5Q92kmM44oWikKptCy_zIM_Roe30TPjXxweE_WjV1fMZaAX6UFumikrtWCTcb9rLnSjpHYFgo-buS7cBXg_nK7xgOPz-bQvv8edVWsBWPf92B9Mak-LNZla_F5EAOjXrN16ZQ1y4qE94ro051kryqUddfVonmLSjCrCavttfBMugYf-SCbLp0w_QLaT9gA_bMXVzqyLnIj74Sr_JCWAxcYU5RaFmqZLEpowyp-m9XGdBwVS2118K0TooZg"
      $signedRSToken("RS512") == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.dgb3ak_0nwQyLa2Ssmq3Jok-pr9QfVFnw_63YlFXTkq_V8r816VeCOzBRYvVv6ONvKGZDR_3SAqf3UJp1XkXtN-VyJ7VRoSHZ0d0-3DPArxDrIu20uvoQrbm4LqQtwbGPH-B-Z-7Bvfng-iwhOt1S717AepZsgVjQz2gOvBvzFsg_BDZ6nhU-5GOnIRkJ2amUt5N1TXbzKHkNLtMpKlq1BZbdv_xKSHgw_IHQRl9lIIQs_2_NuTgk8nQQiwtb9L1v3Y3KYpYGCBvgohWDcpyUKOv5f2EHekDpj1f_ALltd8gzWhIDgwK5VbBo8JAkLWDRfeTOS0fh0Faenfn551wqA"

      signedRSToken("RS256").verify(rsPublicKey)
      signedRSToken("RS384").verify(rsPublicKey)
      signedRSToken("RS512").verify(rsPublicKey)

  when false:
    test "EC Signature":
      # Checked with https://jwt.io/
      # echo signedECToken("ES256")
      check:
        signedECToken("ES256").header.toBase64 == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
        signedECToken("ES256").claims.toBase64 == "eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        # signedECToken("ES256").verify(ecPublicKey)
        # toJWT("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA").verify(ecPublicKey)

        # $signedECToken("ES256") == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.gDQjM0w-foh2h54D2eNV5JzKa2Y5lwoU168jlj2IImH8DDhGHFrjfjstmXos8zGv9iHFzLp5HPYjOZDV_BqX7Q"

        # eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.gDQjM0w-foh2h54D2eNV5JzKa2Y5lwoU168jlj2IImH8DDhGHFrjfjstmXos8zGv9iHFzLp5HPYjOZDV_BqX7Q"
        # $signedECToken("ES256") was eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.Z70NdbsTiPV5PpE2foY9YSehQCm20naEKPLdCZy_dV2W6uPLJTOY6JvAA9r9gykdxuH6dbTZUPo2yxRjpxJrJg
