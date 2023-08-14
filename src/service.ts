import { Analysis } from './constants';
import { NoImplementationError } from './error';

export default abstract class DetectionService {
  async scan (_targetIP: string, _existingRecord: Analysis | null,  ..._options: []): Promise<Analysis> {
    throw new NoImplementationError('service: No implementation');
  }

  get name (): string {
    throw new NoImplementationError('service: No implementation');
  }
}
