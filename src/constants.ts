const namespace = 'validate-my-address';
export enum ScoringRisk {
  Safe = 0,
  Suspicious = 1,
  Unknown = 2
}
export enum Action {
  Whitelist = 'whitelist',
  Blacklist = 'blacklist'
}
export enum Fingerprint {
  Residential = 'residential',
  Tor = 'tor',
  Proxy = 'proxy/vpn',
  Unidentified = 'unidentified'
}
export interface Analysis {
  recommendedAction: Action
  fingerprint: Fingerprint
  targetIp: string
  requiresRescan: boolean
  originCountry?: string
  lastQueried?: number
}
export interface HttpErrorMessage {
  message: string
}
export const ANALYSIS_KEY_FIELD = `${namespace}:analysis`;
export const EXPIRATION_RECHECK = 60 * 60 * 1000 * 6;
export const SCORING_LOW_RISK_THRESHOLD = 0.20;
