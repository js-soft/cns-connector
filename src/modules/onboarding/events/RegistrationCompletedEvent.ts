import { DataEvent } from "@js-soft/ts-utils";

export interface RegistrationCompletedEventData {
    userId: string;
    sessionId?: string;
    password?: string;
}

export class RegistrationCompletedEvent extends DataEvent<RegistrationCompletedEventData> {
    private static readonly namespace = "onboarding.registrationCompleted";
    public constructor(data: RegistrationCompletedEventData) {
        super(RegistrationCompletedEvent.namespace, data);
    }
}
