import json, strutils, tables

import utils

type
    CryptoException* = object of Exception
    UnsupportedAlgorithm* = object of CryptoException

    SignatureAlgorithm* = enum
        NONE
        HS256
        HS384
        HS512
        RS256
        RS384
        RS512

    JOSEHeader* = object
        alg*: SignatureAlgorithm
        typ*: string


proc strToSignatureAlgorithm(s: string): SignatureAlgorithm =
    try:
        result = parseEnum[SignatureAlgorithm](s)
    except ValueError:
        raise newException(UnsupportedAlgorithm, "$# isn't supported" % s)


proc toHeader*(j: JsonNode): JOSEHeader =
    let algStr = j["alg"].str
    let algo = strToSignatureAlgorithm(algStr)

    # Check that the keys are present so we dont blow up.
    utils.checkKeysExists(j, "alg", "typ")

    result = JOSEHeader(
        alg: algo,
        typ: j["typ"].str
    )


proc `%`*(alg: SignatureAlgorithm): JsonNode =
    let s = $alg
    return %s


proc `%`*(h: JOSEHeader): JsonNode =
    return %{
        "alg": %h.alg,
        "typ": %h.typ
    }


proc toBase64*(h: JOSEHeader): string =
    let asJson = %h
    result = encodeUrlSafe($asJson)
