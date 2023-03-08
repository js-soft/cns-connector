import { ApplicationError, Result } from "@js-soft/ts-utils";
import {
    CreateAttributeRequestItemJSON,
    ProprietaryStringJSON,
    RelationshipAttributeConfidentiality,
    RequestItemGroupJSON,
    RequestItemJSONDerivations,
    RequestJSON,
    ResponseJSON
} from "@nmshd/content";
import { CryptoPasswordGenerator } from "@nmshd/crypto";
import { LocalRequestDTO, OutgoingRequestCreatedAndCompletedEvent } from "@nmshd/runtime";
import { QRCode } from "@nmshd/runtime/dist/useCases/common";
import { ParamsDictionary, Request, Response } from "express-serve-static-core";
import { DateTime } from "luxon";
import { ParsedQs } from "qs";
import { ConnectorRuntimeModule, ConnectorRuntimeModuleConfiguration } from "../../ConnectorRuntimeModule";
import { HttpMethod } from "../../infrastructure";
import { OnboardingCompletedEvent, RegistrationCompletedEvent } from "./events";
import { LoginCompletedEvent } from "./events/LoginCompletedEvent";
import { IdentityProvider, IDPResult, KeycloakClientConfig, KeycloakIdentityProvider, RegistrationType } from "./identityProviders";
import { OnboardingConfig } from "./OnboardingConfig";

export interface OnboardingModuleConfig extends ConnectorRuntimeModuleConfiguration, KeycloakClientConfig, OnboardingConfig {}

export default class Onboarding extends ConnectorRuntimeModule<OnboardingModuleConfig> {
    private idp: IdentityProvider;
    private passwordStore?: Map<string, { userId?: string; pw: string }>;

    public async init(): Promise<void> {
        this.idp = new KeycloakIdentityProvider(this.configuration);
        if (this.configuration.passwordStrategy === "setByRequest") {
            this.passwordStore = new Map();
        }

        try {
            await this.idp.initialize();
        } catch (e: any) {
            const err = new Error("Keycloak connection / setup was not successfull");
            err.stack = e.stack;
            throw err;
        }
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/qrCode", false, async (req, res) => {
            await this.createQRCode(req, res);
        });
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/onboarding", false, async (req, res) => {
            await this.handleOnboardingRequest(req, res);
        });
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/registration", false, async (req, res) => {
            await this.handleRegistrationRequest(req, res);
        });
        if (this.configuration.authenticateUsersByEnmeshedChallenge) {
            this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/login", false, async (req, res) => {
                await this.handleLoginRequest(req, res);
            });
        }
    }

    public start(): void {
        this.subscribeToEvent(OutgoingRequestCreatedAndCompletedEvent, this.handleOutgoingRequestCreatedAndCompleted.bind(this));
    }

    private async handleOutgoingRequestCreatedAndCompleted(event: OutgoingRequestCreatedAndCompletedEvent) {
        const data = event.data;
        const responseSourceType = data.response?.source?.type;
        if (!responseSourceType) {
            // We only care about Relationship Changes
            return;
        }

        if (responseSourceType === "Message") {
            if (!this.configuration.authenticateUsersByEnmeshedChallenge) {
                // Message is only interesting if login is enabled
                return;
            }

            const metadata = data.content.metadata as any;

            if (
                data.content.items[0]["@type"] !== "AuthenticationRequestItem" ||
                data.content.items[0].title !== "Login Request" ||
                !metadata ||
                !metadata.__createdByConnectorModule
            ) {
                // This message is not a login request and or not created by us
                return;
            }

            const loginResult = await this.handleEnmeshedLogin(data);

            this.runtime.eventBus.publish(
                new LoginCompletedEvent({
                    success: loginResult?.tokens ? true : false,
                    data: loginResult,
                    sessionId: metadata.sId
                })
            );
            return;
        }
        const changeId = data.response!.source!.reference;
        const templateId = data.source!.reference;
        // This only works if you can guarantee that the template is only used once (max num of allocations: 1)
        const relationship = (await this.runtime.transportServices.relationships.getRelationships({ query: { "template.id": templateId } })).value[0];
        const template = (await this.runtime.transportServices.relationshipTemplates.getRelationshipTemplate({ id: templateId })).value;
        const metadata: any = (
            template.content as {
                "@type": "RelationshipTemplateContent";
                title?: string;
                metadata?: object;
                onNewRelationship: any;
                onExistingRelationship?: any;
            }
        ).metadata;
        if (!metadata?.__createdByConnectorModule) {
            // We only care about relationships changes initiated by our module which are marked in the metadata
            return;
        }

        if (metadata.login) {
            // This is a failed login request
            this.runtime.eventBus.publish(
                new LoginCompletedEvent({
                    success: false,
                    data: undefined,
                    sessionId: metadata.sId
                })
            );
            return;
        }
        const type = metadata.type;
        if (!type) {
            // Relationship changes we initiatet have tho type meta tag
            return;
        }
        const itemGroup = data.content.items[0] as RequestItemGroupJSON;
        let userId;
        switch (this.configuration.userIdStrategy) {
            case "setByRequest": {
                userId = ((itemGroup.items[1] as CreateAttributeRequestItemJSON).attribute.value as any).value as string;
                break;
            }
            case "enmeshedAddress": {
                userId = data.peer;
                break;
            }
            case "enmeshedRelationshipId": {
                userId = relationship.id;
                break;
            }
        }
        const change: ResponseJSON = data.response!.content;

        switch (type) {
            case RegistrationType.Newcommer:
                let password: string;
                switch (this.configuration.passwordStrategy) {
                    case "randomPassword": {
                        password = await CryptoPasswordGenerator.createElementPassword();
                        break;
                    }
                    case "randomKey": {
                        password = await CryptoPasswordGenerator.createStrongPassword();
                        break;
                    }
                    case "setByRequest": {
                        password = this.passwordStore!.get(templateId)!.pw;
                        break;
                    }
                }
                const registrationResult = await this.idp.register(change, userId, password);
                switch (registrationResult) {
                    case IDPResult.Success: {
                        const r = await this.runtime.transportServices.relationships.acceptRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        if (r.isError) {
                            await this.runtime.transportServices.relationships.rejectRelationshipChange({
                                relationshipId: relationship.id,
                                changeId,
                                content: {}
                            });
                            this.runtime.eventBus.publish(
                                new RegistrationCompletedEvent({
                                    success: false,
                                    data: undefined,
                                    errorMessage: "Connector error trying to accept relationship change."
                                })
                            );
                        } else {
                            this.runtime.eventBus.publish(
                                new RegistrationCompletedEvent({
                                    success: true,
                                    data: {
                                        userId,
                                        sessionId: metadata.webSessionId,
                                        password,
                                        onboardingId: templateId
                                    }
                                })
                            );
                        }
                        break;
                    }
                    case IDPResult.Error: {
                        await this.runtime.transportServices.relationships.rejectRelationshipChange({
                            relationshipId: relationship.id,
                            changeId,
                            content: {}
                        });
                        this.runtime.eventBus.publish(
                            new RegistrationCompletedEvent({
                                success: false,
                                data: undefined,
                                errorMessage: "IDP Error trying to create a new user."
                            })
                        );
                        break;
                    }
                }
                break;
            case RegistrationType.Onboarding:
                const onboardingResult = await this.idp.onboard(change, userId);
                switch (onboardingResult) {
                    case IDPResult.Success: {
                        const r = await this.runtime.transportServices.relationships.acceptRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        if (r.isError) {
                            await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                            this.runtime.eventBus.publish(
                                new OnboardingCompletedEvent({
                                    success: false,
                                    data: undefined,
                                    errorMessage: "Connector error trying to accept relationship change."
                                })
                            );
                        } else {
                            this.runtime.eventBus.publish(
                                new OnboardingCompletedEvent({
                                    success: true,
                                    data: {
                                        userId,
                                        sessionId: metadata.webSessionId,
                                        onboardingId: templateId
                                    }
                                })
                            );
                        }
                        break;
                    }
                    case IDPResult.Error: {
                        await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        this.runtime.eventBus.publish(
                            new OnboardingCompletedEvent({
                                success: false,
                                data: undefined,
                                errorMessage: "IDP Error trying to onboard user."
                            })
                        );
                        break;
                    }
                }
                break;
        }
    }

    private async createQRCode(req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>, res: Response<any, Record<string, any>, number>) {
        const body = req.body;
        if (!body.data) {
            res.status(400).send("Specify the truncated reference under the data field.");
            return;
        }
        const qr = await QRCode.from(body.data, "tr");
        const qrBase64 = qr.asBase64();
        const imageBuffer = Buffer.from(qrBase64, "base64");
        res.status(200).send(arrayBufferToStringArray(imageBuffer));
    }

    private async handleOnboardingRequest(req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>, res: Response<any, Record<string, any>, number>): Promise<any> {
        const body = req.body;
        const user = await this.idp.getUser(body.userId as string);
        if (body.userId && user) {
            const templateResult = await this.createTemplate(RegistrationType.Newcommer, body.userId as string, body.sId as string | undefined);
            if (templateResult.isError) {
                return res.status(templateResult.error.code as unknown as number).send(templateResult.error.message);
            }
            return res.status(201).send(templateResult.value);
        }
        res.status(404).send("User not found!");
    }

    private async handleRegistrationRequest(
        req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
        res: Response<any, Record<string, any>, number>
    ): Promise<any> {
        const body = req.body;
        let password: string | undefined;
        switch (this.configuration.passwordStrategy) {
            case "setByRequest": {
                if (!body.password) {
                    return res
                        .status(400)
                        .send(
                            "The module is configured in a way so that you need to pass a password, that will be used to create the account, in order to create a account with enmeshed."
                        );
                }
                password = body.password as string;
            }
            default: {
                // Nothing to do here for us since the password will be generated automatically when the relationship is accepted
            }
        }

        if (!body.userId && this.configuration.userIdStrategy === "setByRequest") {
            return res.status(400).send("To create a username with the custom userIdStrategy you need to pass it");
        }

        const templateResponse = await this.createTemplate(
            RegistrationType.Newcommer,
            this.configuration.userIdStrategy === "setByRequest" ? (body.userId as string) : undefined,
            body.sId as string | undefined
        );
        if (templateResponse.isError) {
            return res.status(templateResponse.error.code as unknown as number).send(templateResponse.error.message);
        }
        if (this.configuration.passwordStrategy === "setByRequest") {
            this.passwordStore!.set(templateResponse.value.templateId, { userId: body.userId as string | undefined, pw: password! });
        }

        return res.status(201).send(templateResponse.value);
    }

    /*  This function is responsible for creating a QR-Request for a login with enmeshed.
     *  To later associate the login request with a given session it needs to be passed in the query.
     *  This could be done with a proxy that simply ads the session id to the request and forwards it to this module. */
    private async handleLoginRequest(req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>, res: Response<any, Record<string, any>, number>): Promise<any> {
        const body = req.body;
        if (!body.sId) {
            return res.status(400).send("You need to specify the session id to later associate the login reuest with that session.");
        }
        const templateResult = await this.createTemplate(RegistrationType.Newcommer, undefined, body.sId as string, true);

        if (templateResult.isError) {
            return res.status(templateResult.error.code as unknown as number).send(templateResult.error.message);
        }
        return res.status(201).send(templateResult.value);
    }

    private async handleEnmeshedLogin(request: LocalRequestDTO): Promise<{ target: string; tokens?: string } | undefined> {
        const peer = request.peer;
        const relationship = await this.runtime.consumptionServices.attributes.getAttributes({
            query: {
                "content.key": "userId",
                "shareInfo.peer": peer
            }
        });
        if (relationship.isError) {
            return undefined;
        }
        const userId = (relationship.value[0].content.value as ProprietaryStringJSON).value;
        const tokens = await this.idp.login!(userId);
        return { target: userId, tokens };
    }

    private async createTemplate(type: RegistrationType, userId?: string, sId?: string, login?: boolean): Promise<Result<{ reference: string; templateId: string }>> {
        const identity = (await this.runtime.transportServices.account.getIdentityInfo()).value;

        const sharableDisplayName = await this.getOrCreateConnectorDisplayName(identity.address, this.configuration.displayName);

        const createItems: RequestItemJSONDerivations[] = [
            {
                "@type": "ShareAttributeRequestItem",
                mustBeAccepted: true,
                attribute: { ...sharableDisplayName.content, owner: "" },
                sourceAttributeId: sharableDisplayName.id
            }
        ];

        const proposedItems: RequestItemJSONDerivations[] = [];

        const requestItems: RequestItemJSONDerivations[] = [];

        if (userId) {
            createItems.push({
                "@type": "CreateAttributeRequestItem",
                mustBeAccepted: true,
                attribute: {
                    "@type": "RelationshipAttribute",
                    owner: identity.address,
                    key: "userId",
                    value: {
                        "@type": "ProprietaryString",
                        title: `${this.configuration.displayName}.userId`,
                        value: userId
                    },
                    isTechnical: false,
                    confidentiality: RelationshipAttributeConfidentiality.Public
                }
            });
        }

        let requestedData: string[] = [];

        if (this.configuration.userData?.req) {
            requestedData = requestedData.concat(this.configuration.userData.req);
        }

        if (this.configuration.userData?.opt) {
            requestedData = requestedData.concat(this.configuration.userData.opt);
        }

        let existingValues: Map<string, string>;

        if (type === RegistrationType.Onboarding) {
            existingValues = await this.idp.getExistingUserInfo(userId!, requestedData);
        } else {
            existingValues = new Map();
        }

        this.configuration.userData?.req?.forEach((element) => {
            const proposedValue = existingValues.get(element);
            if (proposedValue) {
                proposedItems.push({
                    "@type": "ProposeAttributeRequestItem",
                    attribute: {
                        "@type": "IdentityAttribute",
                        owner: "",
                        value: {
                            "@type": "IdentityAttributeQuery" as any,
                            value: proposedValue
                        }
                    },
                    query: {
                        "@type": "IdentityAttributeQuery",
                        valueType: element as any
                    },
                    mustBeAccepted: true
                });
            } else {
                requestItems.push({
                    "@type": "ReadAttributeRequestItem",
                    query: {
                        "@type": "IdentityAttributeQuery",
                        valueType: element as any
                    },
                    mustBeAccepted: true
                });
            }
        });

        this.configuration.userData?.opt?.forEach((optionalElement) => {
            const proposedValue = existingValues.get(optionalElement);
            if (proposedValue) {
                proposedItems.push({
                    "@type": "ProposeAttributeRequestItem",
                    attribute: {
                        "@type": "IdentityAttribute",
                        owner: "",
                        value: {
                            "@type": "IdentityAttributeQuery" as any,
                            value: proposedValue
                        }
                    },
                    query: {
                        "@type": "IdentityAttributeQuery",
                        valueType: optionalElement as any
                    },
                    mustBeAccepted: false
                });
            } else {
                requestItems.push({
                    "@type": "ReadAttributeRequestItem",
                    query: {
                        "@type": "IdentityAttributeQuery",
                        valueType: optionalElement as any
                    },
                    mustBeAccepted: false
                });
            }
        });

        const createObject: RequestItemGroupJSON = {
            "@type": "RequestItemGroup",
            mustBeAccepted: createItems.some((el) => el.mustBeAccepted),
            title: "Shared Attributes",
            items: createItems
        };

        const proposedObject: RequestItemGroupJSON = {
            "@type": "RequestItemGroup",
            mustBeAccepted: proposedItems.some((el) => el.mustBeAccepted),
            title: "Requested Attributes",
            items: proposedItems
        };

        const requestObject: RequestItemGroupJSON = {
            "@type": "RequestItemGroup",
            mustBeAccepted: requestItems.some((el) => el.mustBeAccepted),
            title: "Requested Attributes",
            items: requestItems
        };

        const filteredItemObject = [createObject, proposedObject, requestObject].filter((el) => el.items[0]);

        const onNewRelationship: RequestJSON = {
            "@type": "Request",
            items: filteredItemObject
        };
        const requestPlausible = await this.runtime.consumptionServices.outgoingRequests.canCreate({ content: onNewRelationship });

        if (!requestPlausible.isSuccess) {
            return Result.fail(requestPlausible.error);
        }

        if (!requestPlausible.value.isSuccess) {
            return Result.fail(new ApplicationError("400", requestPlausible.value.message ?? ""));
        }

        let onExistingRelationship;

        if (this.configuration.authenticateUsersByEnmeshedChallenge) {
            onExistingRelationship = {
                metadata: {
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    __createdByConnectorModule: true,
                    webSessionId: sId,
                    type: type
                },
                items: [
                    {
                        "@type": "AuthenticationRequestItem",
                        title: "Login Request",
                        description: "There has been a login request if you did not initiate it please ignore this message and do not approve!",
                        mustBeAccepted: true,
                        reqireManualDecision: true
                    }
                ]
            };
        }

        // Template erstellen
        const template = await this.runtime.transportServices.relationshipTemplates.createOwnRelationshipTemplate({
            maxNumberOfAllocations: 1,
            content: {
                "@type": "RelationshipTemplateContent",
                title: "Connector Demo Contact",
                metadata: {
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    __createdByConnectorModule: true,
                    login,
                    type: type
                },
                onNewRelationship,
                onExistingRelationship: onExistingRelationship
            },
            expiresAt: DateTime.now().plus({ days: 2 }).toISO()
        });

        if (template.isError) {
            return Result.fail(template.error);
        }

        const token = await this.runtime.transportServices.relationshipTemplates.createTokenForOwnTemplate({ templateId: template.value.id });

        if (token.isError) {
            return Result.fail(token.error);
        }


        return Result.ok({ reference: token.value.truncatedReference, templateId: template.value.id });
    }

    private async getOrCreateConnectorDisplayName(connectorAddress: string, displayName: string) {
        const response = await this.runtime.consumptionServices.attributes.getAttributes({
            query: {
                "content.owner": connectorAddress,
                "content.value.@type": "DisplayName"
            }
        });

        if (response.value.length > 0) {
            return response.value[0];
        }

        const createAttributeResponse = await this.runtime.consumptionServices.attributes.createAttribute({
            content: {
                "@type": "IdentityAttribute",
                owner: connectorAddress,
                value: {
                    "@type": "DisplayName",
                    value: displayName
                }
            }
        });

        return createAttributeResponse.value;
    }

    public stop(): void {
        this.unsubscribeFromAllEvents();
    }
}

function arrayBufferToStringArray(buffer: ArrayBuffer): string[] {
    const uInt8A = new Uint8Array(buffer);
    let i = uInt8A.length;
    const biStr = [];
    while (i--) {
        biStr[i] = String.fromCharCode(uInt8A[i]);
    }
    return biStr;
}
