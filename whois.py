#!/usr/bin/env python

###############################################################################
# WHOIS Tool for VNNIC
#
# Copyright (c) 2013 Nguyen Viet Cuong <mrcuongnv@gmail.com>
###############################################################################

import requests
import logging
import re
from urlparse import urljoin
from lxml import etree as ET
from random import choice

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s')

class VNNIC(object):
    AGENTS = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:19.0) Gecko/20100101 Firefox/19.0',
              'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.97 Safari/537.11',
              'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MDDR; .NET4.0C; .NET4.0E; .NET CLR 1.1.4322; Tablet PC 2.0)',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22',
              'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.2')
    
    LANG = {'domain_name':          'Domain Name',
            'dns_servers':          'Name Servers',
            'expiration_date':      'Expiration Date',
            'creation_date':        'Creation Date',
            'registration_date':    'Registration Date',
            'registrant':           'Registrant Name',
            'trade_name':           'Registrant Company',
            'current_registrar':    'Registrar',
            'address':              'Registrant Address'}
    
    def __init__(self):
        pass
    
    
    def whois(self, domain):
        """
        Get domain information via VNNIC
        """
        whois = {}
        
        s = requests.Session()
        s.headers.update({'User-Agent': choice(VNNIC.AGENTS)})
        
        ##
        # Get started cookies
        ##
        url_homepage = 'http://www.vnnic.vn/tenmien/'
        
        r = s.get(url_homepage)
        if r.status_code != requests.codes.ok:
            raise Exception('Request to VNNIC home page unsuccessfully: %d' % r.status_code)
        else:
            logging.info('Access VNNIC home page successfully.')
        
        # Get the list of domain level 2
        url_domain = 'http://whois.vnnic.vn/tenmien/'
        top_domains = {}
        
        r = s.get(url_domain)
        if r.status_code != requests.codes.ok:
            logging.warn('Cannot get the list of domain level 2')
        else:
            html = ET.fromstring(r.text, parser=ET.HTMLParser())
            for e in html.find('.//select').iter(tag='option'):
                top_domain = e.text.strip().lower()
                if top_domain.endswith('.vn'):
                    top_domains[top_domain] = True
        
        ##
        # Get whois URL & Key
        ##
        url_search = 'http://whois.vnnic.vn/tenmien/jsp/tracuudomain1.jsp'
        s.headers.update({'Referer': url_homepage})
        
        tmp = domain
        while True:
            dp = tmp.find('.')
            if dp != -1:
                if top_domains and top_domains.has_key(tmp[dp:]):
                    data = {'domainname1':  tmp[:dp],
                            'cap2':         tmp[dp:],
                            'B3':           '  Submit  '}
                    logging.info('Search for domain: %s' % tmp)
                    break
                else:
                    tmp = tmp[dp+1:]
            else:
                logging.error('Not a Vietnam\'s domain: %s' % domain)
                return None
        
        r = s.post(url_search, data=data)
        if r.status_code != requests.codes.ok:
            logging.error('Request to VNNIC WhoIs unsuccessfully: %d' % r.status_code)
            return None
        else:
            logging.info('Search domain "%s" successfully.' % domain)
        
        # Get the details
        s.headers.update({'Referer': url_homepage})

        html = ET.fromstring(r.text, parser=ET.HTMLParser())
        url_detail = None
        for e in html.iterfind('.//a'):
            if e.attrib.has_key('href') and e.attrib['href'].startswith('tracuudomainchitiet'):
                url_detail = urljoin(url_search, e.attrib['href'])
        if url_detail is None:
            logging.error('Domain "%s" not found or unrecognized detail URL.' % domain)
            return None
        
        r = s.get(url_detail)
        if r.status_code != requests.codes.ok:
            logging.error('Cannot get the domain detailed information: %d' % r.status_code)
            return None
        else:
            logging.info('Got the detailed information of "%s"' % domain)
            
        s.close()
        
        # Parse the details
        html = ET.fromstring(r.text, parser=ET.HTMLParser())
        e_detail = None
        for e in html.iterfind('.//tr'):
            for t in e.itertext():
                if t.find('DOMAINNAME'):
                    e_detail = e.getparent()
                    break
        if e_detail is not None:
            for e in e_detail.iter(tag='tr'):
                ec = e.getchildren()
                if len(ec) == 2 and ec[0].tag == ec[1].tag and ec[0].tag in ('td', 'th'):
                    key   = ' '.join([t.strip() for t in ec[0].itertext()]).strip().lower()
                    value = ' '.join([t.strip() for t in ec[1].itertext()]).strip()
                    if key.find('domainname') != -1:
                        whois['domain_name'] = value
                    elif re.search('dns\s+server', key, re.I):
                        whois['dns_servers'] = [t.strip() for t in value.split('+') if t.strip() != '']
                    elif key.find('expiration') != -1:
                        whois['expiration_date'] = value
                    elif key.find('creation') != -1:
                        whois['creation_date'] = value
                    elif key.find('registration') != -1:
                        whois['registration_date'] = value
                    elif key.find('registrant') != -1:
                        whois['registrant'] = value
                    elif key.find('trade') != -1:
                        whois['trade_name'] = value
                    elif key.find('registrar') != -1:
                        whois['current_registrar'] = value
                    elif key.find('address') != -1:
                        whois['address'] = value
        else:
            logging.error('Cannot parse the detailed information.')
            return None
        
        if whois:
            return whois
        else:
            return None
    

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print >>sys.stderr, 'WHOIS Tool for VNNIC (c) 2013 Nguyen Viet Cuong'
        print >>sys.stderr, '-----------------------------------------------'
        print >>sys.stderr, 'Syntax: python %s <Domain Name>' % __file__
        sys.exit(1)
    
    vnnic = VNNIC()
    whois = vnnic.whois(sys.argv[1])
    if whois is not None:
        for key, value in whois.iteritems():
            print '%-20s: %s' % (VNNIC.LANG[key], value)
    