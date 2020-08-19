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
  ec256PrivKey = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"""
  ec256PubKey = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"""

  ec384PrivKey = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhske
enT+rAyyPhGgBwYFK4EEACKhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+
T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLU
PeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END EC PRIVATE KEY-----"""
  ec384PubKey = """-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----"""
  ec512PrivKey = """-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx
0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn
P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+
duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv
VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==
-----END EC PRIVATE KEY-----"""
  ec512PubKey = """-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----"""


proc signedRSToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(rsPrivateKey)

proc signedECToken(alg, key: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(key)

suite "Token tests":
  test "Load from JSON and verify":
    # Load a token from json
    var
      token = getToken()
      secret = "secret"

    token.sign(secret)

    let b64Token = $token
    token = b64Token.toJWT
    check token.verify(secret, token.header.alg) == true

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

      signedRSToken("RS256").verify(rsPublicKey, RS256)
      signedRSToken("RS384").verify(rsPublicKey, RS384)
      signedRSToken("RS512").verify(rsPublicKey, RS512)

  test "EC Signature":
    # Checked with https://jwt.io/
    # echo signedECToken("ES256")
    check:
      signedECToken("ES256", ec256PrivKey).header.toBase64 == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
      signedECToken("ES256", ec256PrivKey).claims.toBase64 == "eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ"

      $signedECToken("ES256", ec256PrivKey) == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.Z70NdbsTiPV5PpE2foY9YSehQCm20naEKPLdCZy_dV2W6uPLJTOY6JvAA9r9gykdxuH6dbTZUPo2yxRjpxJrJg"
      $signedECToken("ES384", ec384PrivKey) == "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.OkBilspLWGezXYP0A2i5nIT98makjx5RSgDol4N8_vgvyiUpJK5IaI-xGEJ5iJbIASR-YJT4zfPcMdEiPGd6LxBhinYl8EuTDyaipwdYHj1t_DzrsadqxAtlKXtcPGmj"
      $signedECToken("ES512", ec512PrivKey) == "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.AWJbyLizFO3Hbz71V5WtvFRMluPEll3PxqyW9Hze3WI_3xyrxr48UCa5m3Vj60nUKfx3qMTSrc-onHPNFWr4XuadATyrybfhaGiTe0KL5H2V3nO3dC2uSD-lqLL9OXq_YgBwpbvqP1w5RslTfYg3lpCXGy4i6zWPCIfARwNJ3IdkFoFW"

      # signedECToken("ES256").verify(ecPublicKey, ES256)
      # toJWT("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA").verify(ecPublicKey)


      # eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.gDQjM0w-foh2h54D2eNV5JzKa2Y5lwoU168jlj2IImH8DDhGHFrjfjstmXos8zGv9iHFzLp5HPYjOZDV_BqX7Q"
      # $signedECToken("ES256") was eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.Z70NdbsTiPV5PpE2foY9YSehQCm20naEKPLdCZy_dV2W6uPLJTOY6JvAA9r9gykdxuH6dbTZUPo2yxRjpxJrJg
