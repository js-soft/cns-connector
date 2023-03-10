import { ResponseJSON } from "@nmshd/content";

export interface IdentityProvider {
    initialize(): Promise<void>;
    onboard(change: ResponseJSON, userId: string, enmeshedAddress: string): Promise<IDPResult>;
    register(change: ResponseJSON, userId: string, password: string, enmeshedAddress: string): Promise<IDPResult>;
    getUser(userId: string): Promise<object | undefined>;
    login?(userId: string): Promise<string | undefined>;
    getExistingUserInfo(userId: string, requestedData: string[]): Promise<Map<string, string>>;
}

export enum IDPResult {
    Success,
    Error
}
