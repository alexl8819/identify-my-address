declare module 'getipintel' {
  interface SessionOptions {
    contact: string,
    port?: 443,
    timeout?: 6000,
    cacheTime?: 3600,
    rateLimit?: true,
  }
  export interface IPIntel {
    status: string,
    result: string,
    queryIP: string,
    BadIP: number,
    Country: string,
    ts: number
  }
  export default class GetIPIntel {
    constructor (options?: SessionOptions);
    getIntel(IP: string, flags?: string, oflags?: string): Promise<IPIntel>;
  }
}