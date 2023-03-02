import { DataEvent } from "@js-soft/ts-utils";

export interface OnboardingCompletedEventData {
    userId: string;
    sessionId?: string;
}

export class OnboardingCompletedEvent extends DataEvent<OnboardingCompletedEventData> {
    private static readonly namespace = "onboarding.onboardingCompleted";
    public constructor(data: OnboardingCompletedEventData) {
        super(OnboardingCompletedEvent.namespace, data);
    }
}
