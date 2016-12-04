JWT Implementation for Nim-lang
===============================

This is a implementation of JSON Web Tokens for Nim, it allows for the following operations to be performed:

`proc toJWT*(node: JsonNode): JWT` - parse a JSON object representing a JWT token to create a JWT token object.

`proc toJWT*(s: string): JWT` - parse a base64 string to decode it to a JWT token object

`sign*(token: var JWT, secret: var string)` - sign a token. Creates a `signature` property on the given token and assigns the signature to it.

`proc verify*(token: JWT, secret: var string): bool` - verify a token (typically on your incoming requests)

`proc $*(token: JWT): string` - creates a b64url string from the token

## Example

An example to demonstrate use with a userId

```nim
import jwt, times, json, tables

var secret = "secret"

proc sign*(userId: string): string =
  var token = toJWT(%*{
      "header": {
        "alg": "HS256",
        "typ": "JWT"
      },
      "claims": {
        "userId": userId,
        "exp": (getTime() + 1.days).toSeconds().int
      }
    })

  token.sign(secret)

  result = $token

proc verify*(token: string): bool =
  try:
    let jwtToken = token.toJWT()
    result = jwtToken.verify(secret)
  except InvalidToken:
    result = false

proc decode*(token: string): string =
  let jwt = token.toJWT()
  result = $jwt.claims["userId"].node.str

```
