import { decodeProtectedHeader, decodeJwt, flattenedVerify, importJWK, type JWK } from "jose";
import { sha256Canonical } from "./canonical.js";

export type ResolutionAuthorizationClaims = {
  schemaVersion: "resolution-authorization-v1";
  authorizationId: string;
  transaction: {
    transactionId: string;
    orderId: string;
    disputedLineItemIds: string[];
  };
  parties: Array<{
    principalId: string;
    role: "claimant" | "respondent";
    authorityRef: string;
  }>;
  appointment: {
    administrator: string;
    tribunal: string;
    caseMode: string;
    procedureProfile: string;
  };
  legalContext: {
    termsAtrHash: string;
    clauseId: string;
    rulesSha256: string;
    catalogSha256: string;
    providerId: string;
    serviceId: string;
  };
  claimScope: { claimType: string; requestedRemedy: string };
  remedyCeiling: { action: string; currency: string; amountMinorUnits: string };
  issuedAt: string;
  expiresAt: string;
};

export type GeneralJws = {
  payload: string;
  signatures: Array<{ protected: string; signature: string }>;
};

export type AuthorizationTrustKey = JWK & {
  kid: string;
  principalId: string;
  role: "claimant" | "respondent";
};

export class AuthorizationVerificationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AuthorizationVerificationError";
  }
}

export async function verifyBilateralAuthorization(input: {
  jws: GeneralJws;
  trustedKeys: AuthorizationTrustKey[];
  expected: {
    transactionId: string;
    orderId: string;
    disputedLineItemIds: string[];
    termsAtrHash: string;
    clauseId: string;
    rulesSha256: string;
    catalogSha256: string;
    providerId: string;
    serviceId: string;
  };
  now: Date;
}): Promise<{ claims: ResolutionAuthorizationClaims; artifactHash: string; signerKids: string[] }> {
  if (input.jws.signatures.length !== 2) {
    throw new AuthorizationVerificationError("authorization_signatures_invalid", "Exactly two signatures are required.");
  }

  const signerKids: string[] = [];
  const roles = new Set<string>();
  for (const signature of input.jws.signatures) {
    const protectedHeader = decodeProtectedHeader({
      payload: input.jws.payload,
      protected: signature.protected,
      signature: signature.signature,
    });
    if (protectedHeader.alg !== "EdDSA" || typeof protectedHeader.kid !== "string") {
      throw new AuthorizationVerificationError("authorization_signature_header_invalid", "Each signature must use EdDSA and a trusted kid.");
    }
    const trusted = input.trustedKeys.find((candidate) => candidate.kid === protectedHeader.kid);
    if (!trusted) throw new AuthorizationVerificationError("authorization_key_untrusted", `Untrusted kid ${protectedHeader.kid}.`);
    const key = await importJWK(trusted, "EdDSA");
    await flattenedVerify(
      { payload: input.jws.payload, protected: signature.protected, signature: signature.signature },
      key,
      { algorithms: ["EdDSA"] },
    );
    signerKids.push(trusted.kid);
    roles.add(trusted.role);
  }
  const signerPrincipalIds = input.trustedKeys
    .filter((key) => signerKids.includes(key.kid))
    .map((key) => key.principalId);
  if (
    new Set(signerKids).size !== 2 ||
    new Set(signerPrincipalIds).size !== 2 ||
    !roles.has("claimant") ||
    !roles.has("respondent")
  ) {
    throw new AuthorizationVerificationError("authorization_bilateral_missing", "Distinct claimant and respondent signatures are required.");
  }

  let claims: ResolutionAuthorizationClaims;
  try {
    claims = decodeJwt(input.jws.payload) as unknown as ResolutionAuthorizationClaims;
  } catch {
    const json = Buffer.from(input.jws.payload, "base64url").toString("utf8");
    claims = JSON.parse(json) as ResolutionAuthorizationClaims;
  }
  if (claims.schemaVersion !== "resolution-authorization-v1") {
    throw new AuthorizationVerificationError("authorization_schema_invalid", "Unsupported authorization schema.");
  }
  const issuedAt = Date.parse(claims.issuedAt);
  const expiresAt = Date.parse(claims.expiresAt);
  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    issuedAt > input.now.getTime() ||
    expiresAt <= input.now.getTime()
  ) {
    throw new AuthorizationVerificationError("authorization_time_invalid", "Authorization is not active at the verification time.");
  }

  const expected = input.expected;
  const claimedLines = [...claims.transaction.disputedLineItemIds].sort();
  const expectedLines = [...expected.disputedLineItemIds].sort();
  const exactLines = claimedLines.length === expectedLines.length && claimedLines.every((value, index) => value === expectedLines[index]);
  const bindingMatches =
    claims.transaction.transactionId === expected.transactionId &&
    claims.transaction.orderId === expected.orderId &&
    exactLines &&
    claims.legalContext.termsAtrHash === expected.termsAtrHash &&
    claims.legalContext.clauseId === expected.clauseId &&
    claims.legalContext.rulesSha256 === expected.rulesSha256 &&
    claims.legalContext.catalogSha256 === expected.catalogSha256 &&
    claims.legalContext.providerId === expected.providerId &&
    claims.legalContext.serviceId === expected.serviceId;
  if (!bindingMatches) {
    throw new AuthorizationVerificationError("authorization_binding_mismatch", "Authorization does not bind the expected transaction and legal context.");
  }

  const signedPrincipals = input.trustedKeys
    .filter((key) => signerKids.includes(key.kid))
    .map((key) => `${key.principalId}:${key.role}`)
    .sort();
  const claimedPrincipals = claims.parties.map((party) => `${party.principalId}:${party.role}`).sort();
  if (signedPrincipals.join("\n") !== claimedPrincipals.join("\n")) {
    throw new AuthorizationVerificationError("authorization_principal_mismatch", "Signers do not match the appointed principals.");
  }

  return {
    claims,
    artifactHash: sha256Canonical(input.jws),
    signerKids: signerKids.sort(),
  };
}
