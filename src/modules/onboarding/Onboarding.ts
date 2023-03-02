import { CreateAttributeRequestItemJSON, RelationshipAttributeConfidentiality, RequestItemGroupJSON, RequestItemJSONDerivations, RequestJSON, ResponseJSON } from "@nmshd/content";
import { OutgoingRequestCreatedAndCompletedEvent } from "@nmshd/runtime";
import { ParamsDictionary, Request, Response } from "express-serve-static-core";
import { DateTime } from "luxon";
import { ParsedQs } from "qs";
import { ConnectorRuntimeModule, ConnectorRuntimeModuleConfiguration } from "../../ConnectorRuntimeModule";
import { HttpMethod } from "../../infrastructure";
import { OnboardingCompletedEvent, RegistrationCompletedEvent } from "./events";
import { IdentityProvider, IdentityProviderConfig, KeycloakIdentityProvider, RegistrationType, Result } from "./identityProviders";

export interface OnboardingModuleConfig extends ConnectorRuntimeModuleConfiguration, IdentityProviderConfig {}

export default class Onboarding extends ConnectorRuntimeModule<OnboardingModuleConfig> {
    private idp: IdentityProvider;
    private passwordStore?: Map<string, { userId?: string; pw: string }>;

    public async init(): Promise<void> {
        this.idp = new KeycloakIdentityProvider(this.configuration);
        if (this.configuration.passwordStrategy === "ownPassword") {
            this.passwordStore = new Map();
        }

        try {
            await this.idp.initialize();
        } catch (e: any) {
            const err = new Error("Keycloak connection / setup was not successfull");
            err.stack = e.stack;
            throw err;
        }
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Get, "/onboardingQR", false, async (req, res) => {
            await this.handleOnboardingQrRequest(req, res);
        });
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Get, "/registrationQR", false, async (req, res) => {
            await this.handleRegistrationQrRequest(req, res);
        });
    }

    public start(): void {
        this.subscribeToEvent(OutgoingRequestCreatedAndCompletedEvent, this.handleOutgoingRequestCreatedAndCompleted.bind(this));
    }

    private async handleOutgoingRequestCreatedAndCompleted(event: OutgoingRequestCreatedAndCompletedEvent) {
        const data = event.data;
        const responseSourceType = data.response?.source?.type;
        if (!responseSourceType || responseSourceType === "Message") {
            // We only care about Relationship Changes
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

        const itemGroup = data.content.items[0] as RequestItemGroupJSON;

        const userId = ((itemGroup.items[1] as CreateAttributeRequestItemJSON).attribute.value as any).value as string;

        const type = metadata.type;

        if (!type) {
            // Relationship changes we initiatet have tho type meta tag
            return;
        }

        const change: ResponseJSON = data.response!.content;

        switch (type) {
            case RegistrationType.Newcommer:
                let password: string;
                switch (this.configuration.passwordStrategy) {
                    case "securePassword": {
                        // TODO: implement secure password generation
                        password = "secure";
                        break;
                    }
                    case "randomPassword": {
                        // TODO: implement random password generation
                        password = "random";
                        break;
                    }
                    case "ownPassword": {
                        password = this.passwordStore!.get(templateId)!.pw;
                        break;
                    }
                }
                const registrationResult = await this.idp.register(change, userId, password);
                switch (registrationResult) {
                    case Result.Success: {
                        await this.runtime.transportServices.relationships.acceptRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        this.runtime.eventBus.publish(
                            new RegistrationCompletedEvent({
                                userId,
                                sessionId: metadata.webSessionId,
                                password: metadata.password
                            })
                        );
                        break;
                    }
                    case Result.Error: {
                        await this.runtime.transportServices.relationships.rejectRelationshipChange({
                            relationshipId: relationship.id,
                            changeId,
                            content: {}
                        });
                        // TODO: Extend RegistrationCompletedEvent so that it can send error messages
                        break;
                    }
                }
                break;
            case RegistrationType.Onboarding:
                const onboardingResult = await this.idp.onboard(change, userId);
                switch (onboardingResult) {
                    case Result.Success: {
                        await this.runtime.transportServices.relationships.acceptRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        this.runtime.eventBus.publish(
                            new OnboardingCompletedEvent({
                                userId,
                                sessionId: metadata.webSessionId
                            })
                        );
                        break;
                    }
                    case Result.Error: {
                        await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        // TODO: Extend OnboardingCompletedEvent so that it can send error messages
                        break;
                    }
                }
                break;
        }
    }

    private async handleOnboardingQrRequest(
        req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
        res: Response<any, Record<string, any>, number>
    ): Promise<any> {
        const query = req.query;

        const user = await this.idp.getUser(query.userId as string);

        if (query.userId && user) {
            const qrBytes: ArrayBuffer = (await this.createQRCode(RegistrationType.Newcommer, query.userId as string, query.sId as string | undefined))[0];

            return res.send(arrayBufferToStringArray(qrBytes)).status(200);
        }
        res.status(404).send("User not found!");
    }

    private async handleRegistrationQrRequest(
        req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
        res: Response<any, Record<string, any>, number>
    ): Promise<any> {
        const query = req.query;
        let password: string | undefined;
        switch (this.configuration.passwordStrategy) {
            case "ownPassword": {
                if (!query.password) {
                    return res
                        .status(400)
                        .send(
                            "The module is configured in a way so that you need to pass a password, that will be used to create the account, in order to create a account with enmeshed."
                        );
                }
                password = query.password as string;
            }
            default: {
                // Nothing to do here for us since the password will be generated automatically when the relationship is accepted
            }
        }

        if (!query.userId && this.configuration.userIdStrategy === "custom") {
            return res.status(400).send("To create a username with the custom userIdStrategy you need to pass it");
        }

        const response: [ArrayBuffer, string] = await this.createQRCode(RegistrationType.Newcommer, query.userId as string | undefined, query.sId as string | undefined);

        if (this.configuration.passwordStrategy === "ownPassword") {
            this.passwordStore!.set(response[1], { userId: query.userId as string | undefined, pw: password! });
        }

        return res.status(200).send(arrayBufferToStringArray(response[0]));
    }

    private async createQRCode(type: RegistrationType, userId?: string, sId?: string): Promise<[ArrayBuffer, string]> {
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
                    key: "userName",
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

        if (!requestPlausible.value.isSuccess) {
            return [new ArrayBuffer(0), ""];
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
                    webSessionId: sId,
                    type: type
                },
                onNewRelationship,
                onExistingRelationship: {
                    metadata: {
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
                }
            },
            expiresAt: DateTime.now().plus({ days: 2 }).toISO()
        });

        const image = await this.runtime.transportServices.relationshipTemplates.createTokenQrCodeForOwnTemplate({ templateId: template.value.id });

        return [Buffer.from(image.value.qrCodeBytes, "base64"), template.value.id];
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
