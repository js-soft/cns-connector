export interface OnboardingConfig {
    passwordStrategy: "randomPassword" | "randomKey" | "setByRequest";
    userIdStrategy: "enmeshedAddress" | "enmeshedRelationshipId" | "setByRequest";
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
}
