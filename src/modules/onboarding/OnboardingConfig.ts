export interface OnboardingConfig {
    passwordStrategy: "generateRandomPassword" | "generateRandomKey" | "useGivenPassword";
    // TODO: add truncated enmeshedId option (min 3. zeichen + scale if found) useShortestPossibleEnmeshedAddress
    userIdStrategy: "useEnmeshedAddress" | "useEnmeshedRelationshipId" | "useShortestPossibleEnmeshedAddress" | "useGivenUserId";
    // The userData string list should contain the data that should be requested, if not allready present in the onboarding case, in enmeshed datatypes.
    // The implementation of the IdentityProvider Interface that is being used is responsible for translating between the given enmeshed datatypes and the IDP datatypes
    // Fields that cannot be parced to a enmeshed datatype should result in an error on startup since it is likely a configuration mistake which would leed
    // to unexpected behaviour.
    userData:
        | {
              req: string[] | undefined;
              opt: string[] | undefined;
          }
        | undefined;
    // Login with enmeshed
    authenticateUsersByEnmeshedChallenge: boolean;
    templateExpiresAfterXMinutes: number;
}
