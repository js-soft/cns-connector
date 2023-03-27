import { ApplicationError, Result } from "@js-soft/ts-utils";
import { ProprietaryStringJSON, RelationshipAttributeConfidentiality, RequestItemGroupJSON, RequestItemJSONDerivations, RequestJSON, ResponseJSON } from "@nmshd/content";
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
import { IdentityProviderOnboardingAdapter, KeycloakClientConfig, KeycloakIdentityProvider, RegistrationType } from "./identityProviders";
import { OnboardingConfig } from "./OnboardingConfig";
import { ExpireManager } from "./utils/ExpireManager";

/*  TODO: The Module momentarily uses a wallet attribute to determine if a given enmeshed account is connected to a IDP account.
 *  This should be the other way around in the future so that the Login still works if the user denies the creation of the userId attribute.
 *  If we find a way to search a IDP user by custom attribute this can be done. Otherwise this is a design flaw we are unable to fix,
 *  since it is to unperformant to actually traverse all users to search for a enmeshed address.
 */

export interface OnboardingModuleConfig extends ConnectorRuntimeModuleConfiguration, KeycloakClientConfig, OnboardingConfig {}

export default class Onboarding extends ConnectorRuntimeModule<OnboardingModuleConfig> {
    private idp: IdentityProviderOnboardingAdapter;
    private store: Map<string, { userId?: string; password?: string; sessionId: string }>;
    private expireManager: ExpireManager;

    public async init(): Promise<void> {
        this.idp = new KeycloakIdentityProvider(this.configuration);
        this.store = new Map();
        this.expireManager = new ExpireManager({ minutes: this.configuration.templateExpiresAfterXMinutes });

        try {
            await this.idp.initialize();
        } catch (e: any) {
            const err = new Error("Keycloak connection / setup was not successfull");
            err.stack = e.stack;
            throw err;
        }
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/qrCode", false, async (req, res) => {
            await this.createQRCode(req, res);
            this.cleanupStores();
        });
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/onboarding", false, async (req, res) => {
            await this.handleOnboardingRequest(req, res);
            this.cleanupStores();
        });
        this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/registration", false, async (req, res) => {
            await this.handleRegistrationRequest(req, res);
            this.cleanupStores();
        });
        if (this.configuration.authenticateUsersByEnmeshedChallenge) {
            this.runtime.infrastructure.httpServer.addEndpoint(HttpMethod.Post, "/login", false, async (req, res) => {
                await this.handleLoginRequest(req, res);
                this.cleanupStores();
            });
        }
    }

    public start(): void {
        this.subscribeToEvent(OutgoingRequestCreatedAndCompletedEvent, this.handleOutgoingRequestCreatedAndCompleted.bind(this));
    }

    private cleanupStores() {
        const toDelete = this.expireManager.retrieveExpiredItems();
        toDelete.forEach((ref) => {
            this.store.delete(ref);
        });
    }

    private async handleOutgoingRequestCreatedAndCompleted(event: OutgoingRequestCreatedAndCompletedEvent) {
        const data = event.data;
        const responseSourceType = data.response?.source?.type;
        if (!responseSourceType) {
            // We only care about Relationship Changes
            return;
        }
        if (responseSourceType === "Message") {
            await this.handleIncommingMessage(data);
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
        const type = metadata.type;
        if (!type) {
            // Relationship changes we initiatet have the type meta tag
            return;
        }

        const storeData = this.store.get(templateId);
        if (!storeData) {
            // If we don't have any store data the data has expired we need to communicate this error based on the Type of Template
            switch (type) {
                case RegistrationType.Newcommer:
                    this.runtime.eventBus.publish(
                        new RegistrationCompletedEvent({
                            success: false,
                            data: undefined,
                            errorMessage: "The template and store data have expired",
                            onboardingId: templateId
                        })
                    );
                    await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                    return;
                case RegistrationType.Onboarding:
                    this.runtime.eventBus.publish(
                        new OnboardingCompletedEvent({
                            success: false,
                            data: undefined,
                            errorMessage: "The template and store data have expired",
                            onboardingId: templateId
                        })
                    );
                    await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                    return;
            }
        }
        if (metadata.login) {
            // This is a failed login request
            this.runtime.eventBus.publish(
                new LoginCompletedEvent({
                    success: false,
                    data: undefined,
                    sessionId: storeData!.sessionId,
                    onboardingId: templateId,
                    errorMessage: "This enmeshed account is not connected to the Connector"
                })
            );
            await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
            return;
        }
        if (!storeData!.userId) {
            switch (this.configuration.userIdStrategy) {
                case "useGivenUserId": {
                    // This should not be possible since we checked if the store data ist still valid and with this config the userId is mandatory
                    throw new Error("User ID not found with config: useGivenUserId and valid store.");
                }
                case "useEnmeshedAddress": {
                    storeData!.userId = data.peer;
                    break;
                }
                case "useEnmeshedRelationshipId": {
                    storeData!.userId = relationship.id;
                    break;
                }
                case "useShortestPossibleEnmeshedAddress": {
                    storeData!.userId = await this.getShortestPossibleEnmeshedAddress(relationship.id);
                    break;
                }
            }
        }
        const change: ResponseJSON = data.response!.content;
        const identity = (await this.runtime.transportServices.account.getIdentityInfo()).value;
        switch (type) {
            case RegistrationType.Newcommer:
                if (!storeData!.password) {
                    switch (this.configuration.passwordStrategy) {
                        case "generateRandomPassword": {
                            storeData!.password = await CryptoPasswordGenerator.createElementPassword();
                            break;
                        }
                        case "generateRandomKey": {
                            storeData!.password = await CryptoPasswordGenerator.createStrongPassword();
                            break;
                        }
                        case "useGivenPassword": {
                            // This should not be possible since we checked if the store data ist still valid and with this config the password is mandatory
                            throw new Error("Password not found with config: useGivenUserId and valid store.");
                        }
                    }
                }
                const registrationResult = await this.idp.registerNewUserForRelationshipRequest(change, storeData!.userId, storeData!.password, relationship.peer);
                if (registrationResult.isSuccess) {
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
                                errorMessage: "Connector error trying to accept relationship change.",
                                onboardingId: templateId
                            })
                        );
                    } else {
                        this.runtime.eventBus.publish(
                            new RegistrationCompletedEvent({
                                success: true,
                                data: {
                                    userId: storeData!.userId,
                                    sessionId: storeData!.sessionId,
                                    password: storeData!.password
                                },
                                onboardingId: templateId
                            })
                        );
                        const outgoingRequestResponse = await this.runtime.consumptionServices.outgoingRequests.create({
                            content: {
                                items: [
                                    {
                                        "@type": "CreateAttributeRequestItem",
                                        mustBeAccepted: true,
                                        attribute: {
                                            "@type": "RelationshipAttribute",
                                            owner: identity.address,
                                            key: "userId",
                                            value: {
                                                "@type": "ProprietaryString",
                                                title: `${this.configuration.displayName}.userId`,
                                                value: storeData!.userId
                                            },
                                            isTechnical: false,
                                            confidentiality: RelationshipAttributeConfidentiality.Public
                                        }
                                    }
                                ]
                            },
                            peer: relationship.peer
                        });
                        if (outgoingRequestResponse.isError) {
                            this.logger.error(outgoingRequestResponse.error);
                            return;
                        }
                        const content = outgoingRequestResponse.value.content;

                        const messageResponse = await this.runtime.transportServices.messages.sendMessage({
                            recipients: [relationship.peer],
                            content
                        });
                        if (messageResponse.isError) {
                            this.logger.error(messageResponse.error);
                        }
                    }
                    break;
                } else {
                    await this.runtime.transportServices.relationships.rejectRelationshipChange({
                        relationshipId: relationship.id,
                        changeId,
                        content: {}
                    });
                    this.runtime.eventBus.publish(
                        new RegistrationCompletedEvent({
                            success: false,
                            data: undefined,
                            errorMessage: "IDP Error trying to create a new user.",
                            onboardingId: templateId
                        })
                    );
                    break;
                }

            case RegistrationType.Onboarding:
                const onboardingResult = await this.idp.onboardExistingUserForRelationshipRequest(change, storeData!.userId, relationship.peer);
                if (onboardingResult.isSuccess) {
                    const r = await this.runtime.transportServices.relationships.acceptRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                    if (r.isError) {
                        await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                        this.runtime.eventBus.publish(
                            new OnboardingCompletedEvent({
                                success: false,
                                data: undefined,
                                errorMessage: "Connector error trying to accept relationship change.",
                                onboardingId: templateId
                            })
                        );
                    } else {
                        this.runtime.eventBus.publish(
                            new OnboardingCompletedEvent({
                                success: true,
                                data: {
                                    userId: storeData!.userId,
                                    sessionId: storeData!.sessionId
                                },
                                onboardingId: templateId
                            })
                        );
                        const outgoingRequestResponse = await this.runtime.consumptionServices.outgoingRequests.create({
                            content: {
                                items: [
                                    {
                                        "@type": "CreateAttributeRequestItem",
                                        mustBeAccepted: true,
                                        attribute: {
                                            "@type": "RelationshipAttribute",
                                            owner: identity.address,
                                            key: "userId",
                                            value: {
                                                "@type": "ProprietaryString",
                                                title: `${this.configuration.displayName}.userId`,
                                                value: storeData!.userId
                                            },
                                            isTechnical: false,
                                            confidentiality: RelationshipAttributeConfidentiality.Public
                                        }
                                    }
                                ]
                            },
                            peer: relationship.peer
                        });
                        if (outgoingRequestResponse.isError) {
                            this.logger.error(outgoingRequestResponse.error);
                            return;
                        }
                        const requestContent = outgoingRequestResponse.value.content;

                        const messageResponse = await this.runtime.transportServices.messages.sendMessage({
                            recipients: [relationship.peer],
                            content: requestContent
                        });
                        if (messageResponse.isError) {
                            this.logger.error(messageResponse.error);
                        }
                    }
                    break;
                } else {
                    await this.runtime.transportServices.relationships.rejectRelationshipChange({ relationshipId: relationship.id, changeId, content: {} });
                    this.runtime.eventBus.publish(
                        new OnboardingCompletedEvent({
                            success: false,
                            data: undefined,
                            errorMessage: "IDP Error trying to onboard user.",
                            onboardingId: templateId
                        })
                    );
                    break;
                }
        }
    }

    private async handleIncommingMessage(data: LocalRequestDTO): Promise<void> {
        const metadata = data.content.metadata as any;
        if (data.content.items[0]["@type"] !== "AuthenticationRequestItem" || !metadata || !metadata.__createdByConnectorModule) {
            // This message is not created by us
            return;
        }
        const templateId = data.source?.reference;
        if (data.content.items[0].title === "Login Request") {
            if (!this.configuration.authenticateUsersByEnmeshedChallenge) {
                // Message is only interesting if login is enabled
                return;
            }
            // This should be impossible since the module only produces templates
            if (!templateId) {
                throw new Error("Received a message that is marked as created by the module but was not comunicated via template.");
            }
            // Check if store data has expired
            const sessionId = this.store.get(templateId)?.sessionId;
            if (!sessionId) {
                this.runtime.eventBus.publish(
                    new LoginCompletedEvent({
                        success: false,
                        data: undefined,
                        sessionId: undefined,
                        onboardingId: templateId,
                        errorMessage: `The template '${templateId}' and associated store data have expired.`
                    })
                );
                return;
            }
            const loginResult = await this.handleEnmeshedLogin(data);
            if (loginResult.isError) {
                if (loginResult.error.code === "error.onboarding.authentication.noAssociatedIdpUserToEnmeshedAddress") {
                    this.runtime.eventBus.publish(
                        new LoginCompletedEvent({
                            success: false,
                            data: undefined,
                            sessionId: sessionId,
                            onboardingId: templateId,
                            errorMessage: loginResult.error.message
                        })
                    );
                    return;
                }
                throw new Error("Internal Connector error when handling enmeshed login.");
            }
            this.runtime.eventBus.publish(
                new LoginCompletedEvent({
                    success: loginResult.value.tokens ? true : false,
                    data: loginResult.value,
                    sessionId,
                    onboardingId: templateId
                })
            );
            return;
        }
        if (data.content.items[0].title === "Onboarding Request") {
            if (!templateId) {
                return;
            }
            // if (data.content.)
            await this.handleIDPOnboardingOfExistingEnmeshedUser(data, templateId);
        }
    }

    private async getShortestPossibleEnmeshedAddress(enmeshedAddress: string, length = 4): Promise<string> {
        const addressLength = enmeshedAddress.length;
        const shortestAddress = enmeshedAddress.substring(addressLength - length);
        const user = await this.idp.getUser(shortestAddress);
        if (user) {
            return await this.getShortestPossibleEnmeshedAddress(enmeshedAddress, length + 1);
        }
        return shortestAddress;
    }

    private async handleIDPOnboardingOfExistingEnmeshedUser(request: LocalRequestDTO, templateId: string) {
        const peer = request.peer;
        const relationship = await this.runtime.consumptionServices.attributes.getAttributes({
            query: {
                "content.key": "userId",
                "shareInfo.peer": peer
            }
        });
        if (relationship.isError) {
            return;
        }
        const storeData = this.store.get(templateId);
        if (relationship.value.length > 0) {
            this.runtime.eventBus.publish(
                new OnboardingCompletedEvent({
                    onboardingId: templateId,
                    success: false,
                    data: {
                        userId: storeData?.userId ?? "",
                        sessionId: storeData?.sessionId
                    },
                    errorMessage:
                        "The enmeshed account is allready connected to another IDP account. It is curently not supported to have more than one IDP account linked to your enmeshed account."
                })
            );
            return;
        }
        // Check if we have the necessary data in store to onboard the user
        if (!storeData?.userId) {
            this.runtime.eventBus.publish(
                new OnboardingCompletedEvent({
                    onboardingId: templateId,
                    success: false,
                    data: undefined,
                    errorMessage: "The onboarding template and coresponding store data have expired please request a new one."
                })
            );
            return;
        }
        const user = await this.idp.getUser(storeData.userId);
        if (!user) {
            this.runtime.eventBus.publish(
                new OnboardingCompletedEvent({
                    onboardingId: templateId,
                    success: false,
                    data: {
                        userId: storeData.userId,
                        sessionId: storeData.sessionId
                    },
                    errorMessage: "The IDP userId saved in store could not be found."
                })
            );
            return;
        }
        const onboardingResponse = await this.idp.onboardExistingUserForRelationshipRequest(request.response!.content, storeData.userId, request.peer);

        if (onboardingResponse.isError) {
            this.runtime.eventBus.publish(
                new OnboardingCompletedEvent({
                    onboardingId: templateId,
                    success: false,
                    data: {
                        userId: storeData.userId,
                        sessionId: storeData.sessionId
                    },
                    errorMessage: "Unable to update the IDP user."
                })
            );
        }

        this.runtime.eventBus.publish(
            new OnboardingCompletedEvent({
                onboardingId: templateId,
                success: true,
                data: {
                    userId: storeData.userId,
                    sessionId: storeData.sessionId
                }
            })
        );
        // After onboarding the user we now need to save the userId in the enmeshed wallet
        const identityResponse = await this.runtime.transportServices.account.getIdentityInfo();
        if (identityResponse.isError) {
            throw new Error(identityResponse.error.message);
        }
        const outgoingRequestResponse = await this.runtime.consumptionServices.outgoingRequests.create({
            content: {
                items: [
                    {
                        "@type": "CreateAttributeRequestItem",
                        mustBeAccepted: true,
                        attribute: {
                            "@type": "RelationshipAttribute",
                            owner: identityResponse.value.address,
                            key: "userId",
                            value: {
                                "@type": "ProprietaryString",
                                title: `${this.configuration.displayName}.userId`,
                                value: storeData.userId
                            },
                            isTechnical: false,
                            confidentiality: RelationshipAttributeConfidentiality.Public
                        }
                    }
                ]
            },
            peer: peer
        });
        if (outgoingRequestResponse.isError) {
            this.logger.error(outgoingRequestResponse.error);
            return;
        }
        const requestContent = outgoingRequestResponse.value.content;

        const messageResponse = await this.runtime.transportServices.messages.sendMessage({
            recipients: [peer],
            content: requestContent
        });
        if (messageResponse.isError) {
            this.logger.error(messageResponse.error);
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
        if (!body.userId) {
            return res.status(400).send("The userId property is mandatory.");
        }
        if (!body.sId) {
            return res.status(400).send("The sId property is mandatory, this is needed to later map the emited event to a browser session.");
        }
        const user = await this.idp.getUser(body.userId as string);
        if (user) {
            const templateResult = await this.createTemplate(RegistrationType.Onboarding, body.sId as string, body.userId as string);
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
            case "useGivenPassword": {
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

        if (!body.userId && this.configuration.userIdStrategy === "useGivenUserId") {
            return res.status(400).send("To create a username with the custom userIdStrategy you need to pass it");
        }
        if (!body.sId) {
            return res.status(400).send("The sId property is mandatory, this is needed to later map the emited event to a browser session.");
        }

        const templateResponse = await this.createTemplate(
            RegistrationType.Newcommer,
            body.sId as string,
            this.configuration.userIdStrategy === "useGivenUserId" ? (body.userId as string) : undefined
        );
        if (templateResponse.isError) {
            return res.status(templateResponse.error.code as unknown as number).send(templateResponse.error.message);
        }
        if (this.configuration.passwordStrategy === "useGivenPassword") {
            // This is okay since the createTemplate method inserts this key into the map and it is impossible for it to be gone at this point
            this.store.get(templateResponse.value.templateId)!.password = password;
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
        const templateResult = await this.createTemplate(RegistrationType.Newcommer, body.sId as string, undefined, true);

        if (templateResult.isError) {
            return res.status(templateResult.error.code as unknown as number).send(templateResult.error.message);
        }
        return res.status(201).send(templateResult.value);
    }

    private async handleEnmeshedLogin(request: LocalRequestDTO): Promise<Result<{ target: string; tokens?: unknown }>> {
        const peer = request.peer;
        const relationship = await this.runtime.consumptionServices.attributes.getAttributes({
            query: {
                "content.key": "userId",
                "shareInfo.peer": peer
            }
        });
        if (relationship.isError) {
            return Result.fail(relationship.error);
        }
        if (relationship.value.length === 0) {
            return Result.fail(
                new ApplicationError(
                    "error.onboarding.authentication.noAssociatedIdpUserToEnmeshedAddress",
                    "While handling incomming enmeshed login request: The enmeshed address has an active relationship but is not connected to an IDP account. The user has to onboard enmeshed with an existing account first."
                )
            );
        }
        const userId = (relationship.value[0].content.value as ProprietaryStringJSON).value;
        const tokens = await this.idp.authenticateUserAndReturnSessionCredentials!(userId);
        return Result.ok({ target: userId, tokens });
    }

    private async createTemplate(type: RegistrationType, sId: string, userId?: string, login?: boolean): Promise<Result<{ reference: string; templateId: string }>> {
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
            return Result.fail(new ApplicationError(requestPlausible.value.code!, requestPlausible.value.message ?? ""));
        }

        let onExistingRelationship;

        if (this.configuration.authenticateUsersByEnmeshedChallenge && type !== RegistrationType.Onboarding) {
            onExistingRelationship = {
                metadata: {
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    __createdByConnectorModule: true,
                    type: type
                },
                items: [
                    {
                        "@type": "AuthenticationRequestItem",
                        title: "Login Request",
                        description: "There has been a login request if you did not initiate it please ignore this message and do not approve.",
                        mustBeAccepted: true,
                        reqireManualDecision: true
                    }
                ]
            };
        } else if (this.configuration.authenticateUsersByEnmeshedChallenge) {
            onExistingRelationship = {
                metadata: {
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    __createdByConnectorModule: true,
                    type: type
                },
                items: [
                    {
                        "@type": "AuthenticationRequestItem",
                        title: "Onboarding Request",
                        description: "There has been an onboarding request to connect your enmeshed account to an existing user.",
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
            expiresAt: DateTime.now().plus({ minutes: this.configuration.templateExpiresAfterXMinutes }).toISO()
        });

        if (template.isError) {
            return Result.fail(template.error);
        }

        const token = await this.runtime.transportServices.relationshipTemplates.createTokenForOwnTemplate({ templateId: template.value.id });

        if (token.isError) {
            return Result.fail(token.error);
        }

        // Safe session id if it is present and add the key to the expire list

        this.store.set(template.value.id, { userId, sessionId: sId, password: undefined });
        this.expireManager.addItemToExpire(template.value.id);

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
