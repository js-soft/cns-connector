import { Result } from "@js-soft/ts-utils";
import { ResponseJSON } from "@nmshd/content";

export interface IdentityProviderOnboardingAdapter {
    initialize(): Promise<void>;
    onboardExistingUserForRelationshipRequest(change: ResponseJSON, userId: string, enmeshedAddress: string): Promise<Result<void>>;
    registerNewUserForRelationshipRequest(change: ResponseJSON, userId: string, password: string, enmeshedAddress: string): Promise<Result<void>>;
    getUser(userId: string): Promise<object | undefined>;
    authenticateUserAndReturnSessionCredentials?(userId: string): Promise<unknown | undefined>;
    getExistingUserInfo(userId: string, requestedData: string[]): Promise<Map<string, string>>;
}
