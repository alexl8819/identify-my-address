import Redis from 'ioredis';

import Cache from "../cache";
import { RecordNotFoundError } from '../error';
import { EXPIRATION_RECHECK } from '../constants';

export interface RedisCacheAdapter {
  redisClient: Redis.Redis;
  expiry: number
}

export class RedisCacheAdapter extends Cache {
  constructor (options?: Redis.RedisOptions, expiry?: number) {
    super();
    this.expiry = expiry || EXPIRATION_RECHECK;
    this.redisClient = new Redis(options);
  }

  async getRecord(key: string): Promise<string> {
    const result: string | null = await this.redisClient.get(key);
    if (!result) {
      throw new RecordNotFoundError('RedisCache: Record not found');
    }
    return result;
  }

  setRecord(key: string, record: string): void {
    this.redisClient.setex(key, (this.expiry / 1000), record);
  }
}