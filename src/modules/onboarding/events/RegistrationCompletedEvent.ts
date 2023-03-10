import { DataEvent } from "@js-soft/ts-utils";

interface RegistrationCompletedEventData {
    userId: string;
    sessionId?: string;
    password?: string;
}

export interface RegistrationResult {
    success: boolean;
    data?: RegistrationCompletedEventData;
    errorMessage?: string;
    onboardingId: string;
}

export class RegistrationCompletedEvent extends DataEvent<RegistrationResult> {
    private static readonly namespace = "onboarding.registrationCompleted";
    public constructor(data: RegistrationResult) {
        super(RegistrationCompletedEvent.namespace, data);
    }
}
