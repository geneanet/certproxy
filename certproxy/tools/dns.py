import dns.resolver
import dns.exception
import dns.update
import dns.query
import dns.tsigkeyring
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.name
import dns.message
import dns.rrset
import time
import logging


logger = logging.getLogger('certproxy.tools.misc')

def fetch_records(domain: str, recordtype: str) -> dns.resolver.Answer:
    try:
        return dns.resolver.resolve(domain, recordtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except (dns.resolver.NoNameservers):
        logger.warning('All nameservers failed when trying to resolve domain %s', domain)
        return None
    except (dns.exception.Timeout):
        logger.warning('Timeout when trying to resolve domain %s', domain)
        return None

def fetch_first_record(domain: str, recordtype: str) -> dns.rdata.Rdata:
    records = fetch_records(domain, recordtype)
    if records:
        return records[0]
    else:
        return None

def fetch_acme_zonemaster(domain: str):
    logger.debug('Fetching acme zonemaster for domain %s', domain)

    domain = '_acme-challenge.%s' % (domain)
    record = fetch_first_record(domain, 'CNAME')
    if record:
        while record:
            domain = str(record.target)
            record = fetch_first_record(domain, 'CNAME')

    logger.debug('Found acme record %s', domain)

    domain = domain.split('.')
    subdomain = []
    while len(domain):
        item = domain[0]

        zone = '.'.join(domain)

        record = fetch_first_record(zone, 'SOA')
        if record:
            zonemaster = str(record.mname)
            masterrecord = fetch_first_record(zonemaster, 'A')
            if masterrecord:
                logger.debug('Master for zone %s (subdomain %s) = %s', zone, '.'.join(subdomain), str(masterrecord.address))
                return(zone, '.'.join(subdomain), str(masterrecord.address))
            else:
                logger.error('Zone %s master %s has no A record !', zone, zonemaster)
                return None

        subdomain.append(item)
        domain.pop(0)

    logger.error('No zone master found !')
    return None

def update_record(zone: str, subdomain: str, ttl: int, recordtype: str, recordvalue: any, zonemaster_ip: str, tsig_key: dict):
    logger.debug('Updating record for zone %s (zone master %s): %s %d %s "%s"', zone, zonemaster_ip, subdomain, ttl, recordtype, recordvalue)
    keyring = dns.tsigkeyring.from_text(tsig_key)
    update = dns.update.Update(zone, keyring=keyring)
    update.replace(subdomain, ttl, recordtype, recordvalue)
    dns.query.tcp(update, zonemaster_ip, timeout=10)

def wait_record_consistency(zone: str, subdomain: str, recordtype: str, timeout: float=10, wait: float=1):
    nameservers = [str(ns.target) for ns in fetch_records(zone, 'NS')]

    nameservers_ip = []
    for ns in nameservers:
        records = fetch_records(ns, 'A')
        if records:
            nameservers_ip.extend([str(record.address) for record in records])
        else:
            logger.warning('No IP found for nameserver %s', ns)

    values = set()
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        for ns in nameservers_ip:
            qname = dns.name.from_text('.'.join((subdomain, zone)))
            q = dns.message.make_query(qname, recordtype)
            r = dns.query.udp(q, ns)
            rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.from_text(recordtype))
            for rr in rrset:
                values.add(rr)
        if len(values) == 1:
            logger.debug('Record %s %s consistency reached (%s)', '.'.join((subdomain, zone)), recordtype, values)
            return(values.pop())
        logger.debug('Waiting for record %s %s consistency (%s)', '.'.join((subdomain, zone)), recordtype, values)
        time.sleep(wait)
        values.clear()

    raise Exception('Timeout waiting for %s record consistency (%s) after %f seconds' % ('.'.join((subdomain, zone)), values, timeout))
    