import { promises, setServers } from 'node:dns';
import debug from 'debug';
import { 
  Analysis, 
  Fingerprint, 
  Action,
  EXPIRATION_RECHECK
} from '../constants';
import { UnroutableAddressError } from '../error';
import { camelizeObject } from '../util';
import DetectionService from '../service';

const { resolve } = promises;
const debugLog = debug('service:tor');

// Override and use reliable known public DNS servers
setServers(['1.1.1.1', '8.8.8.8']);

export default class TorDetectionService extends DetectionService {
  async scan(targetIP: string, previousAnalysis: Analysis | null): Promise<Analysis> {
    if (previousAnalysis && Object.entries(previousAnalysis).length !== 0) {
      debugLog(previousAnalysis);
      const reconstructedAnalysis: Analysis = camelizeObject(previousAnalysis);
      const requiresRescan: boolean = reconstructedAnalysis.requiresRescan === true;
      const lastQueried: number = reconstructedAnalysis.lastQueried || 0;
      // Send back cached result if time has not expired or does not require rescan
      if (((Date.now() - lastQueried) <= EXPIRATION_RECHECK) && !requiresRescan) {
        debugLog('Received cached result for: ' + targetIP);
        debugLog(reconstructedAnalysis);
        return reconstructedAnalysis;
      }
      debugLog('Required rescan or past expiration');
    }
    // Check IP is not a tor exit node
    let isTor: boolean = false; 
    try {
      isTor = await _isExitNode(targetIP);
    } catch (err) {
      if (err instanceof UnroutableAddressError) {
        debugLog('Address does not resolve, unlikely a tor node...continue');
        isTor = false;
      }
    }
    debugLog('is tor exit node? ' + isTor);
    // If it is not a tor node, do not assume it is a residential node
    return {
      targetIp: targetIP,
      fingerprint: isTor ? Fingerprint.Tor : Fingerprint.Unidentified,
      requiresRescan: true,
      recommendedAction: Action.Blacklist,
      lastQueried: Date.now(),
    } as Analysis;
  }

  get name() {
    return 'TorDetectService';
  }
}

async function _isExitNode(sourceIP: string, timeout = 10000): Promise<boolean> {
  let answer: string[]; //: ResolveAddress | null = null;
  try {
    answer = await resolve(sourceIP.split('.').reverse().join('.') + '.dnsel.torproject.org');
  } catch (err) {
    throw new UnroutableAddressError('Unresolvable address');
  }
  debugLog(answer);
  return answer.indexOf('127.0.0.2') > -1;
};
