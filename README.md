# identify-my-address
Proxy Detection Microservice

# Motive
The aim of this project is to utilize multiple "proxy detection" services to accurately identify an IP address. I've encountered issues
in the past using a single service to detect if a VPN was being used which resulted in many false positives. This has been helpful for a previous
project where incoming connections were blocked based on the type of connection being used.

Multiple sources are queried simulteanously and you get a single result containing the following fields in the form of an `Analysis`:
- Fingerprint (Tor, Proxy, Residential and Unidentified)
- Recommended Action (Whitelist or Blacklist)
- IP queried (IPv4 or IPv6)
- Required Rescan if there is no determination found (rare case)
- Last queried (in ms)

# Caveats
An entire scan can take up to five seconds if the scan is also trying to identify Tor Nodes due to the nature of DNS lookups. If you require < 1 sec responses, you can comment out Tor scans.

# Extend
If you wish to implement another backend service, simply extend the `DetectionService` class and implement the `scan` and `name` functions. It takes two or more arguments as shown below.

## scan(targetIP: string, existingRecord: Analysis | undefined, ...options): Promise<Analysis>
Use the `targetIP` field to pass queries downstream to other third party services. The `existingRecord` argument is a either an existing `Analysis`
pulled from cache or undefined (meaning it's never been cached). Cache lives up to 6 hours by default as these entries using an LRU (Least-recently used). In the future, settings like this will be configurable. You must return an `Analysis` object based on the data obtained from the third party service with the fields shown above.  

## name(): string
Define the service's name, which is used for debugging purposes.

By default, the cache layer used an LRU to hold cached responses. If you require something more advanced, you may replace the LRU adapter with a Redis adapter by simply importing and replacing it. The RedisCache constructor takes 1 single optional argument of `RedisOptions` based off the `ioredis` package.

# TODO
- Tests for both IPv4 and IPv6
- Configuration through UI (SPA) to disable/enable services

# License
MPL-2.0
