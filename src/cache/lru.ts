import Cache from '../cache';

import LRUCache  from 'lru-cache';
import { EXPIRATION_RECHECK } from '../constants';

export interface LRUCacheAdapter {
  lru: LRUCache<any, any>;
  ttl: number;
}

export class LRUCacheAdapter extends Cache {
  constructor (max = 100, ttl?: number) {
    super();
    this.lru = new LRUCache({
      max,
      maxAge: ttl || EXPIRATION_RECHECK
    });
  }

  getRecord (key: string): string {
    return this.lru.get(key);
  }

  setRecord (key: string, serializedRecord: string): void {
    this.lru.set(key, serializedRecord);
  }
}