export interface KeycloakClientConfig {
    baseUrl: string;
    realm: string;
    client: string;
    admin: {
        username: string;
        password: string;
    };
    automateSetup: boolean;
}
