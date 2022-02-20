import json, strutils, times, tables

import utils


type
    ClaimKind* = enum
        ISS,
        SUB,
        NBF,
        EXP,
        AUD,
        IAT,
        JTI,
        GENERAL

    Claim* = ref ClaimObj
    ClaimObj* {.acyclic.} = object
        node*: JsonNode
        kind*: ClaimKind



proc newClaims*(claims: varargs[tuple[key: string, val: Claim]]): TableRef[string, Claim] =
    result = newTable[string, Claim](claims)


proc newClaim*(k: ClaimKind, node: JsonNode): Claim =
    new result
    result.kind = k
    result.node = node

# ISS
proc newISS*(node: JsonNode): Claim =
    checkJsonNodeKind(node, JString)
    return newClaim(ISS, node)

# SUB
proc newSUB*(node: JsonNode): Claim =
    checkJsonNodeKind(node, JString)
    return newClaim(SUB, node)

# AUD
proc newAUD*(node: JsonNode): Claim =
    if node.kind != JArray and node.kind != JString:
        raise newException(ValueError, "Invalid kind")
    return newClaim(AUD, node)

proc newAUD*(recipients: seq[string]): Claim =
    var node = newJArray()
    for r in recipients:
        node.add(%r)
    result = newAUD(node)

proc newAUD*(recipient: string): Claim = return newAUD(@[recipient])

proc newAUD*(recipients: varargs[string]): Claim = return newAUD(@recipients)


# Claims that have any kind of time
proc newTimeClaim*(k: ClaimKind, j: JsonNode): Claim =
    # Check that the json kind is int..
    checkJsonNodeKind(j, JInt)
    return newClaim(k, j)

proc newTimeClaim*(k: ClaimKind, s: string): Claim =
    return newTimeClaim(k, %parseInt(s))

proc newTimeClaim*(k: ClaimKind, i: int64): Claim =
    return newTimeClaim(k, %i)

# Returns the claimKeyms value as a time
proc getClaimTime*(c: Claim): Time =
  result = fromUnix(c.node.num)

# NBF
proc newNBF*(s: string): Claim = return newTimeClaim(NBF, s)

proc newNBF*(j: JsonNode): Claim = return newTimeClaim(NBF, j)

proc newNBF*(i: int64): Claim = return newTimeClaim(NBF, i)

# EXP
proc newEXP*(s: string): Claim = return newTimeClaim(EXP, s)

proc newEXP*(j: JsonNode): Claim = return newTimeClaim(EXP, j)

proc newEXP*(i: int64): Claim = return newTimeClaim(EXP, i)

# IAT
proc newIAT*(s: string): Claim = return newTimeClaim(IAT, s)

proc newIAT*(j: JsonNode): Claim = return newTimeClaim(IAT, j)

proc newIAT*(i: int64): Claim = return newTimeClaim(IAT, i)

# JTI
proc newJTI*(j: JsonNode): Claim =
    assert j.kind == JString
    return newClaim(JTI, j)

proc newJTI*(s: string): Claim =
    return newJTI(%s)


proc toClaims*(j: JsonNode): TableRef[string, Claim] =
    result = newClaims()

    for claimKey, claimNode in j:
        case claimKey:
            of "iss":
                result[claimKey] = newISS(claimNode)
            of "sub":
                result[claimKey] = newSUB(claimNode)
            of "aud":
                result[claimKey] = newAUD(claimNode)
            of "nbf":
                result[claimKey] = newNBF(claimNode)
            of "exp":
                result[claimKey] = newEXP(claimNode)
            of "iat":
                result[claimKey] = newIAT(claimNode)
            of "jti":
                result[claimKey] = newJTI(claimNode)
            else:
                result[claimKey] = newClaim(GENERAL, claimNode)


proc `%`*(c: Claim): JsonNode =
    result = c.node


proc `%`*(claims: TableRef[string, Claim]): JsonNode =
    result = newJObject()
    for k, v in claims:
        result[k] = %v


proc toBase64*(claims: TableRef[string, Claim]): string =
    let asJson = %claims
    result = encodeUrlSafe($asJson)
