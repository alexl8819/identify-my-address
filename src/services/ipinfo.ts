import { IPinfoWrapper, IPinfo, Privacy } from 'node-ipinfo';
import countries from 'i18n-iso-countries';
import debug from 'debug';
import {
  ScoringRisk,
  Analysis,
  Fingerprint,
  Action,
  EXPIRATION_RECHECK,
} from '../constants';
import { camelizeObject } from '../util';
import {
  UnknownServiceError,
  MissingAPIKeyError,
  MissingFieldError,
} from '../error';
import DetectionService from '../service';

const IP_INFO_TOKEN: string = process.env.IP_INFO_TOKEN || '';
const debugLog = debug('service:ipinfo');

if (!IP_INFO_TOKEN) {
  throw new MissingAPIKeyError('An API token must be used to access the IP Info API');
}

export interface IPInfoDetectionService {
  ipInfo: IPinfoWrapper;
}

// Requires standard tier
export class IPInfoDetectionService extends DetectionService {
  constructor () {
    super();
    this.ipInfo = new IPinfoWrapper(IP_INFO_TOKEN);
  }
  async scan (targetIP: string, previousAnalysis: Analysis | null): Promise<Analysis> {
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
    // Check IP is not a public proxy/VPN
    let ipInfoResult: IPinfo | null = null;
    try {
      ipInfoResult = await this.ipInfo.lookupIp(targetIP);
    } catch (err) {
      ipInfoResult = JSON.parse((err as Error).message);
    }
    if (!ipInfoResult) {
      throw new UnknownServiceError('ipinfo: Something went wrong due to an unknown error encountered.');
    } else if (!ipInfoResult.privacy) {
      throw new MissingFieldError('ipinfo: Privacy field not found, privacy detection requires a standard plan to use.');
    }
    debugLog(ipInfoResult);
    // Analyze result based on score
    const risk: ScoringRisk = _analyzeRisk(ipInfoResult.privacy);
    // Get country origin (if available)
    let originCountry: string | undefined;
    // If country is included in result, add it in
    if (ipInfoResult.countryCode) {
      originCountry = countries.getName(ipInfoResult.countryCode, 'en', {
        select: 'official'
      });
    }
    // If safe score, send back whitelist otherwise blacklist
    return {
      originCountry,
      targetIp: targetIP,
      fingerprint: ipInfoResult.privacy['tor'] ? Fingerprint.Tor : (risk === ScoringRisk.Safe ? Fingerprint.Residential : Fingerprint.Proxy),
      requiresRescan: false,
      recommendedAction: risk === ScoringRisk.Safe ? Action.Whitelist : Action.Blacklist,
      lastQueried: Date.now(),
    } as Analysis;
  }

  get name() {
    return 'IPInfoDetectionService';
  }
};

export default IPInfoDetectionService; 

function _analyzeRisk (privacy: Privacy): ScoringRisk {
  if (privacy['proxy'] || privacy['vpn'] || privacy['tor'] || privacy['relay'] || privacy['hosting']) { // High risk with good certainty - Unsafe (likely bad/banned IP)
    return ScoringRisk.Suspicious;
  } // Low risk with good certainty - Safe (likely good IP)
  return ScoringRisk.Safe;
}
