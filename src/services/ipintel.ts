import countries from 'i18n-iso-countries';
import GetIPIntel, { IPIntel, SessionOptions } from 'getipintel';
import debug from 'debug';
import {
  ScoringRisk,
  Analysis,
  Fingerprint,
  Action,
  EXPIRATION_RECHECK,
  SCORING_LOW_RISK_THRESHOLD,
} from '../constants';
import { camelizeObject } from '../util';
import {
  MissingContactEmailError,
  UnroutableAddressError,
  InvalidParsedAddressError,
  InvalidInputError,
  BannedError,
  MaintenanceError,
  UnknownServiceError,
} from '../error';
import DetectionService from '../service';

const CONTACT_EMAIL = process.env.CONTACT_EMAIL;
const debugLog = debug('service:ipintel');

if (!CONTACT_EMAIL) {
  throw new MissingContactEmailError('No contact email found. A contract email must be used to access the API');
}

export interface IPIntelDetectionService {
  _intel: GetIPIntel;
}

export class IPIntelDetectionService extends DetectionService {
  constructor () {
    super();
    this._intel = new GetIPIntel(({ 
      contact: CONTACT_EMAIL 
    }) as SessionOptions);
  }
  // TODO - 'm' and 'b' provide too many false positives, use 'f' to ensure
  async scan (targetIP: string, previousAnalysis: Analysis | null, flags: string = 'f', oflags?: string): Promise<Analysis> {
    // Set default flag
    let setFlags: string = 'b';
    debugLog(`IP: ${targetIP} | flags: ${setFlags}`);
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
      setFlags = 'f';
    }
    // Check IP is not a public proxy/VPN
    let ipIntelResult: IPIntel | null = null;
    try {
      ipIntelResult = await this._intel.getIntel(targetIP, flags, oflags);
    } catch (err) {
      ipIntelResult = JSON.parse((err as Error).message) as IPIntel;
    }
    if (!ipIntelResult) {
      throw new UnknownServiceError('ipintel: Missing data due to unknown service error');
    }
    debugLog(ipIntelResult);
    // Parse result as number
    const result: number = parseInt(ipIntelResult.result, 10);
    // Results less than zero indicate error
    if (result < 0) {
      switch (result) {
        case -1: // Invalid no input
          throw new InvalidInputError('Invalid or no input provided');
        case -2: // Invalid IP address
          throw new InvalidParsedAddressError('Invalid IP address encountered');
        case -3: // Unroutable / private address
          throw new UnroutableAddressError('Unroutable or private address encountered');
        case -4: // Unable to reach database (database update or maintenance)
          throw new MaintenanceError('Unable to reach database due to maintenance');
        case -5: // Connecting IP banned
          throw new BannedError('Connecting IP has been banned. Did you exceed query limits or use invalid email address?');
        case -6: // No contact information or contact information is invalid
          throw new MissingContactEmailError('No contact information or contact information is invalid');
      }
    }
    // Analyze result based on score
    const risk: ScoringRisk = _analyzeRisk(result);
    // Get country origin (if available)
    let originCountry: string | undefined;
    // If country is included in result, add it in
    if (ipIntelResult.Country) {
      originCountry = countries.getName(ipIntelResult.Country, 'en', {
        select: 'official'
      });
    }
    // If safe score, send back whitelist otherwise blacklist
    return {
      originCountry,
      targetIp: targetIP,
      fingerprint: risk === ScoringRisk.Safe ? Fingerprint.Residential : Fingerprint.Proxy,
      requiresRescan: risk === ScoringRisk.Unknown,
      recommendedAction: risk === ScoringRisk.Safe ? Action.Whitelist : Action.Blacklist,
      lastQueried: Date.now(),
    } as Analysis;
  }

  get name() {
    return 'IPIntelDetectionService';
  }
};

export default IPIntelDetectionService;
/* 
If a value of 0.50 is returned, then it is as good as flipping a 2 sided fair coin, which implies it's not very accurate. 
From my personal experience, values > 0.95 should be looked at and values > 0.99 are most likely proxies. 
Anything below the value of 0.90 is considered as "low risk". Since a real value is returned, different levels of protection can be implemented. 
It is best for a system admin to test some sample datasets with this system and adjust implementation accordingly. 
I only recommend automated action on high values ( > 0.99 or even > 0.995 ) but it's always best to manually review IPs that return high values. 
For example, mark an order as "under manual review" and don't automatically provision the product for high proxy values. 
Be sure to experiment with the results of this system before you use it live on your projects. 
If you believe the result is wrong, don't hesitate to contact me, I can tell you why. If it's an error on my end, I'll correct it. 
If you email me, expect a reply within 12 hours. */
// Use flag 'm'
function _analyzeRisk (score: number, lowRiskThreshold = SCORING_LOW_RISK_THRESHOLD): ScoringRisk {
  if (score >= 0 && score <= lowRiskThreshold) { // Low risk with good certainty - Safe (likely good IP)
    return ScoringRisk.Safe;
  } else if (score >= 0.99) { // High risk with good certainty - Unsafe (likely bad/banned IP)
    return ScoringRisk.Suspicious;
  }
  return ScoringRisk.Unknown; // Unknown risk - needs more information, should flag for full scan
}
