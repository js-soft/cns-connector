export class Queue<T> {
    private head?: Node<T>;
    private tail?: Node<T>;
    private size: number;

    public constructor() {
        this.head = undefined;
        this.tail = undefined;
        this.size = 0;
    }

    public peek(): T | undefined {
        return this.head?.getValue();
    }

    public dequeue(): T | undefined {
        const toReturn = this.head;
        if (this.size === 1) {
            this.head = undefined;
            this.tail = undefined;
            this.size = 0;
        } else if (this.size > 1) {
            this.head = this.head!.getNext();
            this.size -= 1;
        }
        return toReturn?.getValue();
    }

    public enqueue(value: T): void {
        const newNode = new Node(value);
        if (this.size === 0) {
            this.head = newNode;
            this.tail = newNode;
            this.size = 1;
        } else {
            this.tail!.setNext(newNode);
            this.tail = newNode;
            this.size += 1;
        }
    }
}

class Node<T> {
    private value: T;
    private next?: Node<T>;

    public constructor(value: T) {
        this.value = value;
        this.next = undefined;
    }

    public getValue(): T {
        return this.value;
    }

    public getNext(): Node<T> | undefined {
        return this.next;
    }

    public setValue(value: T) {
        this.value = value;
    }

    public setNext(next: Node<T> | undefined) {
        this.next = next;
    }
}
