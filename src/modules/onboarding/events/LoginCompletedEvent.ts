import { DataEvent } from "@js-soft/ts-utils";

interface LoginResult {
    success: boolean;
    // If the relationship could not be found this will be undefined
    data: TargetDetails | undefined;
    // No matter if success or not the sessionId needs to be communicated to give feedback.
    // This will only be undefined if the Loginrequest expired
    sessionId?: string;
    errorMessage?: string;
    onboardingId: string;
}

interface TargetDetails {
    // Even when the login is unsuccessful we should communicate what userId login was requested
    target: string;
    // The tokens are defined if sucess === true
    tokens?: unknown;
}

export class LoginCompletedEvent extends DataEvent<LoginResult> {
    private static readonly namespace = "onboarding.loginCompleted";
    public constructor(data: LoginResult) {
        super(LoginCompletedEvent.namespace, data);
    }
}
