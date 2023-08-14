// import { setTimeout } from 'node:timers/promises';
import { fetch, setGlobalDispatcher, Agent } from 'undici';
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
  RateLimitError,
} from '../error';
import DetectionService from '../service';

const IP_HUB_APIKEY: string = process.env.IP_HUB_APIKEY || '';
const debugLog = debug('service:iphub');

setGlobalDispatcher(new Agent({ connect: { timeout: 60_000 },  }) );

if (!IP_HUB_APIKEY) {
  throw new MissingAPIKeyError('An API key must be used to access the IP Hub API');
}

interface IPHubAPIResponse {
  ip: string
  countryCode: string
  countryName: string
  asn: number
  isp: string
  block: number
};

// Free tier: 1k per month
export default class IPHubDetectionService extends DetectionService {
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
    const ipHubResult: IPHubAPIResponse = await contactAPI(targetIP);
    if (!ipHubResult) {
      throw new UnknownServiceError('iphub: No data found, API may been under maintenance or have been shutdown.');
    }
    debugLog(ipHubResult);
    // Analyze result based on score
    const risk: ScoringRisk = _analyzeRisk(ipHubResult.block);
    // Get country origin (if available)
    let originCountry: string | undefined;
    // If country is included in result, add it in
    if (ipHubResult.countryCode) {
      originCountry = countries.getName(ipHubResult.countryCode, 'en', {
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
    return 'IPHubDetectionService';
  }
};

function _analyzeRisk (score: number): ScoringRisk {
  if (score === 0) { // Low risk with good certainty - Safe (likely good IP)
    return ScoringRisk.Safe;
  } else if (score === 1) { // High risk with good certainty - Unsafe (likely bad/banned IP)
    return ScoringRisk.Suspicious;
  }
  return ScoringRisk.Unknown; // Unknown risk - needs more information, should flag for full scan
}

async function contactAPI (targetIP: string): Promise<IPHubAPIResponse> {
  /*const controller = new AbortController();
  const apiTimeoutHandler = setTimeout(() => {
    controller.abort();
  }, 5000);*/

  let apiResponse;
  try {
    apiResponse = await fetch(`http://v2.api.iphub.info/ip/${targetIP}`, { 
      headers: {
        'X-Key': IP_HUB_APIKEY
      },
      // signal: controller.signal
    });
  } catch (err) {
    debugLog((err as Error).message);
    throw err;
    // clearTimeout(apiTimeoutHandler);
    //throw new Error('iphub: Fetch timed out');
  }
  
  if (!apiResponse.ok) {
    if (apiResponse.status === 429) {
      throw new RateLimitError('iphub: Service returned a rate limit 429 error response');
    }
    throw new UnknownServiceError(`iphub: Service returned unknown http response (${apiResponse.status}) - ${apiResponse.statusText}`);
  }
  
  return await apiResponse.json() as IPHubAPIResponse;
}
