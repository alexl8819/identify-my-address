import { NoImplementationError } from "./error";

export default abstract class Cache {
  getRecord(_key: string): string | Promise<string> {
    throw new NoImplementationError('getRecord: No implementation exists.');
  }

  setRecord(_key: string, _serializedRecord: string): void | Promise<void> {
    throw new NoImplementationError('setRecord: No implementation exists.')
  }
}