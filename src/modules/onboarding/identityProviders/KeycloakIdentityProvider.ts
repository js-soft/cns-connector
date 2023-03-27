/* eslint-disable @typescript-eslint/naming-convention */
import { ApplicationError, Result } from "@js-soft/ts-utils";
import { ResponseItemGroupJSON, ResponseJSON } from "@nmshd/content";
import AgentKeepAlive, { HttpsAgent } from "agentkeepalive";
import AsyncRetry from "async-retry";
import axios, { AxiosInstance } from "axios";
import { KeycloakUserWithRoles } from "../KeycloakUser";
import { IdentityProviderOnboardingAdapter } from "./IdentityProvider";
import { KeycloakClientConfig } from "./IdentityProviderConfig";
// eslint-disable-next-line @typescript-eslint/no-require-imports
const randExp = require("randexp");

export enum RegistrationType {
    Newcommer = "Newcommer",
    Onboarding = "Onboarding"
}

export class KeycloakIdentityProvider implements IdentityProviderOnboardingAdapter {
    private readonly axios: AxiosInstance;
    public constructor(private readonly config: KeycloakClientConfig) {
        this.axios = axios.create({
            baseURL: this.config.baseUrl,
            httpAgent: new AgentKeepAlive(),
            httpsAgent: new HttpsAgent(),
            validateStatus: () => true,
            maxRedirects: 0
        });
    }

    public async initialize(): Promise<void> {
        const token = await AsyncRetry(async () => await this.getAdminToken("master"), {
            retries: 5,
            minTimeout: 5000
        });
        if (!(await this.isRealmSetup(token))) {
            if (!this.config.automateSetup) throw new Error(`The given realm: ${this.config.realm} is not setup.`);
            await this.setupRealm(token);
        }
        let client;
        if (!(client = await this.isClientSetup(token))) {
            if (!this.config.automateSetup) throw new Error(`The given client: ${this.config.client} is not setup.`);
            await this.setupClient(token);
        } else if (!this.isClientConfigCorrect(client)) {
            if (!this.config.automateSetup) throw new Error(`The given client: ${this.config.client} is not configured correctly.`);
            await this.updateClientConfig(client, token);
        }
        // This function will throw an error if the permissions are not set up correctly and autosetup is disabled.
        // We do it there so the error message is as describing as possible.
        const clientId = await this.checkPermissions(token);
        if (clientId) await this.configurePermissions(clientId, token);
        if (!(await this.hasAdminUser(token))) {
            await this.createAdminUser(token);
        }
    }

    public async onboardExistingUserForRelationshipRequest(change: ResponseJSON, userId: string, enmeshedAddress: string): Promise<Result<undefined>> {
        const userData = getUserData(change, userId, enmeshedAddress);

        const status = await this.updateUser(userData);

        if (status !== 204) {
            return Result.fail(new ApplicationError("error.onboarding.idpError", "There was an error updating the idp user"));
        }
        return Result.ok(undefined);
    }

    public async registerNewUserForRelationshipRequest(change: ResponseJSON, userId: string, password: string, enmeshedAddress: string): Promise<Result<void>> {
        const userData = getUserData(change, userId, enmeshedAddress);

        const status = await this.createUser({
            ...userData,
            ...{ password: password }
        });
        if (status !== 201) {
            return Result.fail(new ApplicationError("error.onboarding.idpError", "There was an error creating the idp user"));
        }
        return Result.ok(undefined);
    }

    public async authenticateUserAndReturnSessionCredentials(userId: string): Promise<string | undefined> {
        const user = await this.getUser(userId);

        if (!user) {
            return undefined;
        }

        const token = await this.impersonate(user.id);

        return token;
    }

    public async getExistingUserInfo(userId: string, requestedData: string[]): Promise<Map<string, string>> {
        const user = await this.getUser(userId);

        const res: Map<string, string> = new Map();

        if (!user) {
            return new Map();
        }

        const normalKeycloakAttributesMap: any = {
            Surname: "lastName",
            GivenName: "firstName",
            EMailAddress: "email",
            Sex: "gender",
            PhoneNumber: "phone"
        };

        for (const element of requestedData) {
            const keycloakName: string | undefined = normalKeycloakAttributesMap[element];
            if (keycloakName && user[keycloakName]) {
                res.set(element, user[keycloakName]);
            } else if (user.attributes?.[element]) {
                res.set(element, user.attributes[element]);
            }
        }

        return res;
    }

    // Impersonate User with admin token
    private async impersonate(userId: string): Promise<any> {
        const adminToken = await this.getAdminToken(this.config.realm);

        const urlencoded = new URLSearchParams();
        urlencoded.append("client_id", "admin-cli");
        urlencoded.append("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        urlencoded.append("subject_token", adminToken);
        urlencoded.append("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token");
        urlencoded.append("audience", this.config.client);
        urlencoded.append("requested_subject", userId);

        const response = await this.axios.post(`/realms/${this.config.realm}/protocol/openid-connect/token`, urlencoded, {
            headers: { authorization: `Bearer ${adminToken}` }
        });

        return response.data;
    }

    private async updateUser(params: {
        userName: string;
        password?: string;
        vorName?: string;
        name?: string;
        email?: string;
        attributes?: Record<string, string>;
        addRoles?: string[];
        removeRoles?: string[];
    }): Promise<number> {
        const adminToken = await this.getAdminToken(this.config.realm);

        const user = await this.getUser(params.userName);

        const credentials = params.password ? [{ type: "password", value: params.password }] : undefined;

        if (!user) {
            return 404;
        }

        const response = await this.axios.put(
            `/admin/realms/${this.config.realm}/users/${user.id}`,
            {
                username: params.userName,
                firstName: params.vorName,
                lastName: params.name,
                email: params.email,
                attributes: params.attributes,
                credentials: credentials
            },
            {
                headers: {
                    authorization: `bearer ${adminToken}`,
                    "content-type": "application/json"
                }
            }
        );

        return response.status;
    }

    private async createUser(params: {
        userName: string;
        password: string;
        firstName?: string;
        lastName?: string;
        email?: string;
        attributes?: Record<string, string>;
        roles?: string[];
    }): Promise<number> {
        try {
            const adminToken = await this.getAdminToken(this.config.realm);

            const response = await this.axios.post(
                `/admin/realms/${this.config.realm}/users`,
                {
                    username: params.userName,
                    enabled: true,
                    firstName: params.firstName,
                    lastName: params.lastName,
                    email: params.email,
                    attributes: params.attributes,
                    credentials: [{ type: "password", value: params.password }]
                },
                {
                    headers: {
                        authorization: `bearer ${adminToken}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            return response.status;
        } catch (e: any) {
            return e.status;
        }
    }

    public async getUser(userName: string): Promise<KeycloakUserWithRoles | undefined> {
        const adminToken = await this.getAdminToken(this.config.realm);

        const response = await this.axios.get(`/admin/realms/${this.config.realm}/users?exact=true&username=${userName}`, {
            headers: { authorization: `Bearer ${adminToken}` }
        });
        const user: KeycloakUserWithRoles | undefined = response.data[0];
        if (!user) return;
        const roleMappingResponse = await this.axios.get(`/admin/realms/${this.config.realm}/users/${user.id}/role-mappings/realm`, {
            headers: { authorization: `Bearer ${adminToken}` }
        });

        user.roles = roleMappingResponse.data.map((el: any) => el.name);
        return user;
    }

    private async createAdminUser(token: string): Promise<void> {
        try {
            await this.axios.post(
                `/admin/realms/${this.config.realm}/users`,
                {
                    username: this.config.admin.username,
                    credentials: [{ type: "password", value: this.config.admin.password }],
                    enabled: true
                },
                {
                    headers: {
                        authorization: `bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );
            const user = await this.axios.get(`/admin/realms/${this.config.realm}/users?exact=true&username=${this.config.admin.username}`, {
                headers: { authorization: `Bearer ${token}` }
            });
            const clientResponse = await this.axios.get(`/admin/realms/${this.config.realm}/clients`, {
                headers: { authorization: `Bearer ${token}` }
            });

            const realmManagementClient = clientResponse.data.filter((el: any) => {
                return el.clientId === "realm-management";
            })[0];

            const roles = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/roles`, {
                headers: { authorization: `Bearer ${token}` }
            });

            await this.axios.post(`/admin/realms/${this.config.realm}/users/${user.data[0].id}/role-mappings/clients/${realmManagementClient.id}`, roles.data, {
                headers: {
                    authorization: `bearer ${token}`,
                    "Content-Type": "application/json"
                }
            });
        } catch (e) {
            throw new Error(`Error creating admin User: \n${e}`);
        }
    }

    private async hasAdminUser(token: string): Promise<boolean> {
        const user = await this.axios.get(`/admin/realms/${this.config.realm}/users?exact=true&username=${this.config.admin.username}`, {
            headers: { authorization: `Bearer ${token}` }
        });
        return user.data.length > 0;
    }

    private async configurePermissions(id: string, token: string) {
        try {
            // Enable permissions for the Client
            await this.axios.put(
                `/admin/realms/${this.config.realm}/clients/${id}/management/permissions`,
                {
                    enabled: true
                },
                {
                    headers: { authorization: `Bearer ${token}` }
                }
            );

            // Get realm-management and admin-cli Client id
            const clientResponse = await this.axios.get(`/admin/realms/${this.config.realm}/clients`, {
                headers: { authorization: `Bearer ${token}` }
            });
            const clientIds = clientResponse.data.filter((el: any) => {
                return el.clientId === "realm-management" || el.clientId === "admin-cli";
            });

            const realmManagementClient = clientIds.find((o: any) => o.clientId === "realm-management");
            const adminCliClient = clientIds.find((o: any) => o.clientId === "admin-cli");
            // Create token exchange policy
            const policyId = new randExp(/\w{20}/).gen();
            await this.axios.post(
                `/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/policy/client`,
                {
                    id: policyId,
                    type: "client",
                    logic: "POSITIVE",
                    decisionStrategy: "UNANIMOUS",
                    name: "token-exchange",
                    clients: [adminCliClient.id]
                },
                {
                    headers: {
                        authorization: `bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            // Get token exchange scope ID
            const scopeIds = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/scope`, {
                headers: { authorization: `Bearer ${token}` }
            });
            const tokenExchangeScopeId = scopeIds.data.find((el: any) => el.name === "token-exchange").id;

            const policyIds = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/policy`, {
                headers: { authorization: `Bearer ${token}` }
            });
            const tokenExchangePolicy = policyIds.data.find((el: any) => el.name.startsWith("token-exchange.permission.client."));

            // Get resourceId
            const resourceIds = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/resource`, {
                headers: { authorization: `Bearer ${token}` }
            });
            const clientResourceId = resourceIds.data.find((el: any) => el.name.startsWith("client.resource."))._id;
            // Activate token-exchange policy
            await this.axios.put(
                `/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/permission/scope/${tokenExchangePolicy.id}`,
                {
                    decisionStrategy: "UNANIMOUS",
                    id: tokenExchangePolicy.id,
                    logic: "POSITIVE",
                    name: tokenExchangePolicy.name,
                    scopes: [tokenExchangeScopeId],
                    resources: [clientResourceId],
                    policies: [policyId],
                    type: "scope"
                },
                {
                    headers: { authorization: `Bearer ${token}` }
                }
            );
        } catch (e) {
            throw new Error(`Error updating client permissions.\n${e}`);
        }
    }

    private async checkPermissions(token: string): Promise<string | undefined> {
        // check if permissions are enabled
        const clientResponse = await this.axios.get(`/admin/realms/${this.config.realm}/clients`, {
            headers: { authorization: `Bearer ${token}` }
        });
        const client = clientResponse.data.filter((el: any) => {
            return el.clientId === this.config.client;
        })[0];
        const clientPermissions = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${client.id}/management/permissions`, {
            headers: { authorization: `Bearer ${token}` }
        });

        if (!clientPermissions.data.enabled) {
            if (!this.config.automateSetup) throw new Error(`Client permissions are not enabled for client: ${this.config.client}`);
            return client.id;
        }

        // check if there is a token exchange policy
        const realmManagementClient = clientResponse.data.filter((el: any) => {
            return el.clientId === "realm-management";
        })[0];
        const policyIds = await this.axios.get(`/admin/realms/${this.config.realm}/clients/${realmManagementClient.id}/authz/resource-server/policy`, {
            headers: { authorization: `Bearer ${token}` }
        });
        if (policyIds.data.some((el: any) => el.name.startsWith("token-exchange.permission.client."))) {
            return;
        }
        if (!this.config.automateSetup) throw new Error(`Client ${this.config.client} does not hate token-exchange permision`);
        return client.id;
    }

    private async updateClientConfig(client: any, token: string): Promise<void> {
        try {
            await this.axios.put(
                `/admin/realms/${this.config.realm}/clients/${client.id}`,
                {
                    standardFlowEnabled: false,
                    directAccessGrantsEnabled: true,
                    publicClient: true,
                    webOrigins: ["*"]
                },
                {
                    headers: {
                        authorization: `bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );
        } catch (e) {
            throw new Error(`Something went wrong updating the Client ${this.config.client} 😢\nPlease make sure the Keycloakserver is running`);
        }
    }

    private isClientConfigCorrect(client: any): boolean {
        return client.webOrigins.includes("*") && !client.standardFlowEnabled && client.directAccessGrantsEnabled && client.publicClient;
    }

    private async setupClient(token: string): Promise<void> {
        try {
            await this.axios.post(
                `/admin/realms/${this.config.realm}/clients`,
                {
                    clientId: `${this.config.client}`,
                    standardFlowEnabled: false,
                    directAccessGrantsEnabled: true,
                    publicClient: true,
                    webOrigins: ["*"]
                },
                {
                    headers: {
                        authorization: `bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );
        } catch (e) {
            throw new Error(`Something went wrong creating the Client ${this.config.client} 😢\nPlease make sure the Keycloakserver is running`);
        }
    }

    private async isClientSetup(token: string): Promise<any> {
        try {
            let client: any;
            const clientResponse = await this.axios.get(`/admin/realms/${this.config.realm}/clients`, {
                headers: { authorization: `Bearer ${token}` }
            });

            if (
                !clientResponse.data.some((el: any) => {
                    if (el.clientId === this.config.client) {
                        client = el;
                        return true;
                    }
                    return false;
                })
            ) {
                return;
            }
            return client;
        } catch (e) {
            throw new Error(`Something went wrong checking for ${this.config.client}, error:\n${e}`);
        }
    }

    private async setupRealm(token: string): Promise<void> {
        try {
            await this.axios.post(
                "/admin/realms",
                {
                    realm: `${this.config.realm}`,
                    enabled: true
                },
                {
                    headers: {
                        authorization: `bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );
        } catch (e) {
            throw new Error(`Something went wrong creating the Realm ${this.config.realm} 😢\nPlease make sure the Keycloakserver is running`);
        }
    }

    private async isRealmSetup(token: string): Promise<boolean> {
        try {
            const realm = await this.axios.get(`/realms/${this.config.realm}`, {
                headers: { authorization: `Bearer ${token}` }
            });
            if (realm.data.error) {
                return false;
            }
            if (!realm.data.enabled) {
                await this.axios.put(
                    `/admin/realms/${this.config.realm}`,
                    {
                        enabled: true
                    },
                    {
                        headers: {
                            authorization: `bearer ${token}`,
                            "Content-Type": "application/json"
                        }
                    }
                );
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    private async getAdminToken(realm: string): Promise<string> {
        const urlencoded = new URLSearchParams();
        urlencoded.append("client_id", "admin-cli");
        urlencoded.append("username", this.config.admin.username);
        urlencoded.append("password", this.config.admin.password);
        urlencoded.append("grant_type", "password");

        const response = await this.axios.post(`/realms/${realm}/protocol/openid-connect/token`, urlencoded);
        const json: any = await response.data;
        return json.access_token;
    }
}

function getUserData(
    request: ResponseJSON,
    userId: string,
    enmeshedAddress: string
): {
    userName: string;
    attributes?: any;
    firstName?: string;
    lastName?: string;
    email?: string;
} {
    const retValue = {
        userName: userId,
        attributes: {
            enmeshedAddress: enmeshedAddress
        },
        firstName: undefined,
        lastName: undefined,
        email: undefined
    };

    const normalKeycloakAttributes = ["Surname", "GivenName", "EMailAddress"];

    const entries = request.items.slice(1) as ResponseItemGroupJSON[];

    const attr: any = {};

    for (const entry of entries) {
        for (const item of entry.items) {
            if (item["@type"] === "ReadAttributeAcceptResponseItem" || item["@type"] === "ProposeAttributeAcceptResponseItem") {
                const el: any = (item as any).attribute;
                if (el?.value) {
                    if (normalKeycloakAttributes.includes(el.value["@type"])) {
                        switch (el.value["@type"]) {
                            case "Surname":
                                retValue.lastName = el.value.value;
                                break;
                            case "GivenName":
                                retValue.firstName = el.value.value;
                                break;
                            case "EMailAddress":
                                retValue.email = el.value.value;
                                break;
                            default:
                                throw new Error("This is not possible");
                        }
                    } else {
                        Object.assign(attr, { [el.value["@type"]]: el.value.value });
                    }
                }
            }
        }
    }

    Object.assign(retValue.attributes, attr);

    return retValue;
}
