import { DateTime, DurationLike } from "luxon";
import { Queue } from "./Queue";

export class ExpireManager {
    private readonly queue: Queue<ToExpire>;
    private readonly expireTime: DurationLike;

    public constructor(expireTime: DurationLike) {
        this.queue = new Queue();
        this.expireTime = expireTime;
    }

    public addItemToExpire(reference: string): void {
        this.queue.push({
            deadline: DateTime.now().plus(this.expireTime),
            reference
        });
    }

    public retrieveExpiredItems(): string[] {
        const deprecatedItems = [];
        while (this.queue.peek() && this.queue.peek()!.deadline < DateTime.now()) {
            deprecatedItems.push(this.queue.pop()!.reference);
        }
        return deprecatedItems;
    }
}

interface ToExpire {
    deadline: DateTime;
    reference: string;
}
