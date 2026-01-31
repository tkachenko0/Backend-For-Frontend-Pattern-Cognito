type Constructor<T> = new (...args: never[]) => T;
type AbstractConstructor<T> = abstract new (...args: never[]) => T;
type Token<T> = Constructor<T> | AbstractConstructor<T>;

export class Container {
  private instances = new Map<Token<unknown>, unknown>();

  register<T>(token: Token<T>, instance: T): void {
    this.instances.set(token, instance);
  }

  get<T>(token: Token<T>): T {
    const instance = this.instances.get(token);
    if (!instance) {
      const name = token.name;
      throw new Error(`Service ${name} not registered`);
    }
    return instance as T;
  }

  has<T>(token: Token<T>): boolean {
    return this.instances.has(token);
  }
}
