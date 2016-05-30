#include <sstream>

#include "checkzone.hh"


vector<pair<string,string>> CheckZone::checkDelegation(const DNSName& zone, UeberBackend &B)
{
  vector<pair<string,string>> retval;
  // Check for delegation in parent zone
  DNSName parent(zone);
  while(parent.chopOff()) {
    SOAData sd_p;
    if(B.getSOAUncached(parent, sd_p)) {
      bool ns=false;
      DNSResourceRecord rr;
      B.lookup(QType(QType::ANY), zone, NULL, sd_p.domain_id);
      while(B.get(rr))
        ns |= (rr.qtype == QType::NS);
      if (!ns) {
        retval.push_back({"Error", "No delegation for zone '"+zone.toString()+"' in parent '"+parent.toString()+"'"});
      }
      break;
    }
  }
  return retval;
}

vector<pair<string,string>> CheckZone::checkZone(DNSSECKeeper &dk, SOAData sd, const DNSName& zone, const vector<DNSResourceRecord>* records, bool directdnskey) 
{
  vector<pair<string,string>> retval;

  NSEC3PARAMRecordContent ns3pr;
  bool narrow = false;
  bool haveNSEC3 = dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  bool isOptOut=(haveNSEC3 && ns3pr.d_flags);

  bool isSecure=dk.isSecuredZone(zone);
  bool presigned=dk.isPresigned(zone);
  bool validKeys=dk.checkKeys(zone);

  DNSResourceRecord rr;
  uint64_t numrecords=0;

  if (haveNSEC3 && isSecure && zone.wirelength() > 222) {
    retval.push_back({"Error", "zone '" + zone.toStringNoDot() + "' has NSEC3 semantics but is too long to have the hash prepended. Zone name is " + std::to_string(zone.wirelength()) + " bytes long, whereas the maximum is 222 bytes."});
  }

  if (!validKeys) {
    retval.push_back({"Error", "zone '" + zone.toStringNoDot() + "' has at least one invalid DNS Private Key."});
  }

  bool hasNsAtApex = false;
  set<DNSName> tlsas, cnames, noncnames, glue, checkglue;
  set<string> recordcontents;
  map<string, unsigned int> ttl;

  ostringstream content;
  pair<map<string, unsigned int>::iterator,bool> ret;

  for(auto rr : *records) { // we modify this
    if(!rr.qtype.getCode())
      continue;

    numrecords++;

    if(rr.qtype.getCode() == QType::TLSA)
      tlsas.insert(rr.qname);
    if(rr.qtype.getCode() == QType::SOA) {
      vector<string>parts;
      stringtok(parts, rr.content);

      ostringstream o;
      o<<rr.content;
      for(int pleft=parts.size(); pleft < 7; ++pleft) {
        o<<" 0";
      }
      rr.content=o.str();
    }

    if(rr.qtype.getCode() == QType::TXT && !rr.content.empty() && rr.content[0]!='"')
      rr.content = "\""+rr.content+"\"";

    try {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
      string tmp=drc->serialize(rr.qname);
      tmp = drc->getZoneRepresentation(true);
      if (rr.qtype.getCode() != QType::AAAA) {
        if (!pdns_iequals(tmp, rr.content)) {
          if(rr.qtype.getCode() == QType::SOA) {
            tmp = drc->getZoneRepresentation(false);
          }
          if(!pdns_iequals(tmp, rr.content)) {
            retval.push_back({"Warning", "Parsed and original record content are not equal: "+rr.qname.toString()+" IN " +rr.qtype.getName()+ " '" + rr.content+"' (Content parsed as '"+tmp+"')"});
          }
        }
      } else {
        struct in6_addr tmpbuf;
        if (inet_pton(AF_INET6, rr.content.c_str(), &tmpbuf) != 1 || rr.content.find('.') != string::npos) {
          retval.push_back({"Warning", "Following record is not a valid IPv6 address: "+rr.qname.toString()+" IN " +rr.qtype.getName()+ " '" + rr.content+"'"});
        }
      }
    }
    catch(std::exception& e)
    {
      retval.push_back({"Error", "Following record had a problem: "+rr.qname.toString()+" IN " +rr.qtype.getName()+ " " + rr.content + "\nError was: " + e.what()});
      continue;
    }

    if(!rr.qname.isPartOf(zone)) {
      retval.push_back({"Error", "Record '"+rr.qname.toString()+" IN "+rr.qtype.getName()+" "+rr.content+"' in zone '"+zone.toString()+"' is out-of-zone."});
      continue;
    }

    content.str("");
    content<<rr.qname.toString()<<" "<<rr.qtype.getName()<<" "<<rr.content;
    if (recordcontents.count(toLower(content.str()))) {
      retval.push_back({"Error", "Duplicate record found in rrset: '"+rr.qname.toString()+" IN "+rr.qtype.getName()+" "+rr.content+"'"});
      continue;
    } else
      recordcontents.insert(toLower(content.str()));

    content.str("");
    content<<rr.qname.toString()<<" "<<rr.qtype.getName();
    if (rr.qtype.getCode() == QType::RRSIG) {
      RRSIGRecordContent rrc(rr.content);
      content<<" ("<<DNSRecordContent::NumberToType(rrc.d_type)<<")";
    }
    ret = ttl.insert(pair<string, unsigned int>(toLower(content.str()), rr.ttl));
    if (ret.second == false && ret.first->second != rr.ttl) {
      retval.push_back({"Error", "TTL mismatch in rrset: '"+rr.qname.toString()+" IN " +rr.qtype.getName()+" "+rr.content+"' ("+std::to_string(ret.first->second)+" != "+std::to_string(rr.ttl)+")"});
      continue;
    }

    if (isSecure && isOptOut && (rr.qname.countLabels() && rr.qname.getRawLabels()[0] == "*")) {
      retval.push_back({"Warning", "wildcard record '"+rr.qname.toString()+" IN " +rr.qtype.getName()+" "+rr.content+"' is insecure\n[Info] Wildcard records in opt-out zones are insecure. Disable the opt-out flag for this zone to avoid this warning. Command: pdnsutil set-nsec3 "+zone.toString()});
    }

    if(rr.qname==zone) {
      if (rr.qtype.getCode() == QType::NS) {
        hasNsAtApex=true;
      } else if (rr.qtype.getCode() == QType::DS) {
        retval.push_back({"Warning", "DS at apex in zone '"+zone.toString()+"', should not be here."});
      }
    } else {
      if (rr.qtype.getCode() == QType::SOA) {
        retval.push_back({"Error", "SOA record not at apex '"+rr.qname.toString()+" IN "+rr.qtype.getName()+" "+rr.content+"' in zone '"+zone.toString()+"'"});
        continue;
      } else if (rr.qtype.getCode() == QType::DNSKEY) {
        retval.push_back({"Warning", "DNSKEY record not at apex '"+rr.qname.toString()+" IN "+rr.qtype.getName()+" "+rr.content+"' in zone '"+zone.toString()+"', should not be here."});
      } else if (rr.qtype.getCode() == QType::NS && DNSName(rr.content).isPartOf(rr.qname)) {
        checkglue.insert(DNSName(toLower(rr.content)));
      } else if (rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) {
        glue.insert(rr.qname);
      }
    }

    if (rr.qtype.getCode() == QType::CNAME) {
      if (!cnames.count(rr.qname))
        cnames.insert(rr.qname);
      else {
        retval.push_back({"Error", "Duplicate CNAME found at '"+rr.qname.toString()+"'"});
        continue;
      }
    } else {
      if (rr.qtype.getCode() == QType::RRSIG) {
        if(!presigned) {
          retval.push_back({"Error", "RRSIG found at '"+rr.qname.toString()+"' in non-presigned zone. These do not belong in the database."});
          continue;
        }
      } else
        noncnames.insert(rr.qname);
    }

    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3)
    {
      retval.push_back({"Error", "NSEC or NSEC3 found at '"+rr.qname.toString()+"'. These do not belong in the database."});
      continue;
    }

    if(!presigned && rr.qtype.getCode() == QType::DNSKEY)
    {
      if(directdnskey)
      {
        if(rr.ttl != sd.default_ttl)
        {
          retval.push_back({"Warning", "DNSKEY TTL of "+std::to_string(rr.ttl)+" at '"+rr.qname.toString()+"' differs from SOA minimum of "+std::to_string(sd.default_ttl)});
        }
      }
      else
      {
        retval.push_back({"Warning", "DNSKEY at '"+rr.qname.toString()+"' in non-presigned zone will mostly be ignored and can cause problems."});
      }
    }

    if ( (rr.qtype.getCode() == QType::NS || rr.qtype.getCode() == QType::SRV || rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::CNAME || rr.qtype.getCode() == QType::DNAME) &&
         rr.content[rr.content.size()-1] == '.') {
      retval.push_back({"Warning", "The record "+rr.qname.toString()+" with type "+rr.qtype.getName()+" has a trailing dot in the content ("+rr.content+"). Your backend might not work well with this."});
    }

    if(rr.auth == 0 && rr.qtype.getCode()!=QType::NS && rr.qtype.getCode()!=QType::A && rr.qtype.getCode()!=QType::AAAA)
    {
      retval.push_back({"Error", "Following record is auth=0, run pdnsutil rectify-zone?: "+rr.qname.toString()+" IN " +rr.qtype.getName()+ " " + rr.content});
    }
  }
  retval.push_back({"numrecords", std::to_string(numrecords)});

  for(auto &i: cnames) {
    if (noncnames.find(i) != noncnames.end()) {
      retval.push_back({"Error", "CNAME "+i.toString()+" found, but other records with same label exist."});
    }
  }

  for(const auto &i: tlsas) {
    DNSName name = DNSName(i);
    name.trimToLabels(name.getRawLabels().size()-2);
    if (cnames.find(name) == cnames.end() && noncnames.find(name) == noncnames.end()) {
      // No specific record for the name in the TLSA record exists, this
      // is already worth emitting a warning. Let's see if a wildcard exist.
      DNSName wcname(name);
      wcname.chopOff();
      wcname.prependRawLabel("*");
      string message;
      if (cnames.find(wcname) != cnames.end() || noncnames.find(wcname) != noncnames.end()) {
        message = "A wildcard record exist for '"+wcname.toString()+"' and a TLSA record for '"+i.toString()+"'.";
      } else {
        message = "No record for '"+name.toString()+"' exists, but a TLSA record for '"+i.toString()+"' does.";
      }
      message += " A query for '"+name.toString()+"' will yield an empty response. This is most likely a mistake, please create records for '"+name.toString()+"'.";
      retval.push_back({"Warning", message});
    }
  }

  if(!hasNsAtApex) {
    retval.push_back({"Error", "No NS record at zone apex in zone '"+zone.toString()+"'"});
  }

  for(const auto &qname : checkglue) {
    if (!glue.count(qname)) {
      retval.push_back({"Warning", "Missing glue for '"+qname.toString()+"' in zone '"+zone.toString()+"'"});
    }
  }

  return retval;
}

