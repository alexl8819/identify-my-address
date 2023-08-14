import { 
  Server,
  createServer,
  ServerResponse, 
  IncomingMessage
} from 'http';
import {
  AddressInfo
} from 'net';
import {
  parse,
  ParsedUrlQuery
} from 'querystring';
import debug  from 'debug';
import {
  Analysis,
  HttpErrorMessage,
} from './constants';
import { isProxy } from './proxy';
import { LRUCacheAdapter } from './cache/lru';
import { InvalidInputError, InvalidParsedAddressError, MissingContactEmailError, UnroutableAddressError } from './error';
import TorDetectionService from './services/tor';
import IPIntelDetectionService from './services/ipintel';
import IPHubDetectionService from './services/iphub';
// import { IPInfoDetectionService } from './services/ipinfo';

const debugLog = debug('http');

// TODO: construct these from a config file?
const activatedServices = new Set([
  new IPIntelDetectionService(), // Free plan
  new IPHubDetectionService(), // Free plan
  new TorDetectionService()
  // new IPInfoDetectionService() // Requires standard plan
]);
const defaultCache = new LRUCacheAdapter();
const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
  if (!req.url || !res.socket) {
    res.end();
    return;
  }

  const remoteAddress: string | undefined = res.socket.remoteAddress;

  if (remoteAddress) {
    debugLog(`Query from: ${remoteAddress}`);
  }

  const qs: ParsedUrlQuery = parse(req.url, '?');
  const queryIp: string = decodeURIComponent(qs['ip'] as string);

  let isProxyResponse: Analysis;
  
  try {
    isProxyResponse = await isProxy(queryIp, activatedServices, defaultCache);
  } catch (err) {
    if (err instanceof InvalidParsedAddressError || err instanceof InvalidInputError || err instanceof UnroutableAddressError || err instanceof MissingContactEmailError) {
      res.statusCode = 400;
    } else {
      res.statusCode = 500;
    }

    res.end(JSON.stringify(
      Object.freeze({
        error: true,
        message: (err as Error).message
      } as HttpErrorMessage)
    ));
    return;
  }

  res.statusCode = 200;
  res.end(JSON.stringify(isProxyResponse));
})
.listen(process.env.LISTENING_PORT || 9000, () => {
  const socketAddress: string | AddressInfo | null = server.address() as AddressInfo;
  debugLog(`Listening on port ${socketAddress.port}`);
});
