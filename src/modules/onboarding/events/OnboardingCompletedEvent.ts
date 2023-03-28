import { DataEvent } from "@js-soft/ts-utils";

interface OnboardingCompletedEventData {
    userId: string;
    sessionId?: string;
}

interface OnboardingResult {
    success: boolean;
    data?: OnboardingCompletedEventData;
    errorMessage?: string;
    onboardingId: string;
}

export class OnboardingCompletedEvent extends DataEvent<OnboardingResult> {
    private static readonly namespace = "onboarding.onboardingCompleted";
    public constructor(data: OnboardingResult) {
        super(OnboardingCompletedEvent.namespace, data);
    }
}
