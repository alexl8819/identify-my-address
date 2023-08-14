import { createHash } from 'crypto';
import { isIP } from 'is-ip';
import pTimeout from 'p-timeout';
import debug from 'debug';

import {
  Action,
  Analysis,
  ANALYSIS_KEY_FIELD,
  Fingerprint
} from './constants';
import {
  InvalidParsedAddressError,
  RecordNotFoundError,
  SaveFailureError,
  NoDetectionServiceError
} from './error';
import { decamelizeObject } from './util';
import Cache from './cache';
import DetectionService from './service';

const debugLog = debug('proxy');

export async function isProxy(targetIP: string, detectionServices: Set<DetectionService>, cache: Cache): Promise<Analysis> {
  // Check if at least one detection service is being used
  if (detectionServices.size === 0) {
    throw new NoDetectionServiceError('proxy: Must define at least one detection service');
  }
  // Check input is valid ip
  if (!isIP(targetIP)) {
    throw new InvalidParsedAddressError('proxy: Not a valid IPv4 or IPv6 address');
  }
  // Check cache for existing entries
  const hashedEntry: string = createHash('sha1').update(targetIP).digest('hex');
  // Create identifier
  const keyIdentifier: string = `${ANALYSIS_KEY_FIELD}_${hashedEntry}`;
  // Query all fields with cache
  let existingRecord: string = '';
  try {
    existingRecord = await cache.getRecord(keyIdentifier);
  } catch (err) {
    debugLog((err as RecordNotFoundError).message);
  }
  // Reconstruct analysis from serialized json
  const previousAnalysis: Analysis | null = existingRecord ? JSON.parse(existingRecord) as Analysis : null;
  // Stage 1: Shallow check using existing services (Tor Exit Nodes, Known public VPN lists, etc)
  const results: PromiseSettledResult<Analysis | undefined>[] = await Promise.allSettled(
    Array.from(detectionServices).map((service: DetectionService) => {
      debugLog(`Awaiting result from: ${service.name}`);
      return pTimeout(service.scan(targetIP, previousAnalysis), {
        milliseconds: 5000 // should not take any longer than five seconds to resolve (even tor queries with a fast DNS resolver)
      });
    })
  );
  debugLog(results);
  const proxyAnalysis: Analysis = await _determineFingerprint(targetIP, results);
  // Stage 2: Cache result for 6 hours (default)
  const decamelized: Record<string, string> = decamelizeObject(Object.assign({}, proxyAnalysis));
  try {
    cache.setRecord(keyIdentifier, JSON.stringify(decamelized));
  } catch (err) {
    throw new SaveFailureError('Error occured creating analysis');
  }
  // Return analysis result
  return Object.freeze(proxyAnalysis);
}

// Determine the correct fingerprint from the analysis
async function _determineFingerprint (targetIP: string, results: PromiseSettledResult<Analysis | undefined>[]): Promise<Analysis> {
  const fulfilled: PromiseFulfilledResult<Analysis>[] = results.filter((result: PromiseSettledResult<Analysis | undefined>) => result && result.status === 'fulfilled') as PromiseFulfilledResult<Analysis>[];
  // Not a single service returned a result, immediately return
  if (!fulfilled.length) {
    return {
      targetIp: targetIP,
      fingerprint: Fingerprint.Unidentified,
      recommendedAction: Action.Blacklist,
      requiresRescan: true,
      originCountry: 'N/A',
      lastQueried: Date.now()
    } as Analysis;
  }
  // Split analysis results into "proxies" and "residential" to determine which has greater likelihood
  const proxyVotes: Set<Analysis> = new Set([]);
  const residentialVotes: Set<Analysis> = new Set([]);
  for (const result of fulfilled) {
    const analysis: Analysis = (result.value as Analysis);
    // If analysis returned a tor fingerprint, immediately return
    if (analysis.fingerprint === Fingerprint.Tor) {
      return analysis;
    } else if (analysis.fingerprint === Fingerprint.Proxy) {
      proxyVotes.add(analysis);
    } else if (analysis.fingerprint === Fingerprint.Residential) {
      residentialVotes.add(analysis);
    }
  }
  // Return based on greater fingerprint likelihood
  if (proxyVotes.size > residentialVotes.size) {
    return Array.from(proxyVotes)[0];
  } else if (residentialVotes.size > proxyVotes.size) {
    return Array.from(residentialVotes)[0];
  }
  // If it is split 50/50, it remains unidentified and should be blacklisted until its rescanned
  return {
    targetIp: targetIP,
    fingerprint: Fingerprint.Unidentified,
    recommendedAction: Action.Blacklist,
    requiresRescan: true,
    originCountry: 'N/A',
    lastQueried: Date.now()
  } as Analysis;
}
