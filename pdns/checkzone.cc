#include "checkzone.hh"

int CheckZone::checkZone(DNSSECKeeper &dk, UeberBackend &B, const DNSName& zone, const vector<DNSResourceRecord>* suppliedrecords, bool g_verbose, bool directdnskey) 
{
  SOAData sd;
  if(!B.getSOAUncached(zone, sd)) {
    cout<<"[error] No SOA record present, or active, in zone '"<<zone.toString()<<"'"<<endl;
    cout<<"Checked 0 records of '"<<zone.toString()<<"', 1 errors, 0 warnings."<<endl;
    return 1;
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow = false;
  bool haveNSEC3 = dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  bool isOptOut=(haveNSEC3 && ns3pr.d_flags);

  bool isSecure=dk.isSecuredZone(zone);
  bool presigned=dk.isPresigned(zone);
  bool validKeys=dk.checkKeys(zone);

  DNSResourceRecord rr;
  uint64_t numrecords=0, numerrors=0, numwarnings=0;

  if (haveNSEC3 && isSecure && zone.wirelength() > 222) {
    numerrors++;
    cout<<"[Error] zone '" << zone.toStringNoDot() << "' has NSEC3 semantics but is too long to have the hash prepended. Zone name is " << zone.wirelength() << " bytes long, whereas the maximum is 222 bytes." << endl;
  }

  if (!validKeys) {
    numerrors++;
    cout<<"[Error] zone '" << zone.toStringNoDot() << "' has at least one invalid DNS Private Key." << endl;
  }

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
        cout<<"[Error] No delegation for zone '"<<zone.toString()<<"' in parent '"<<parent.toString()<<"'"<<endl;
        numerrors++;
      }
      break;
    }
  }


  bool hasNsAtApex = false;
  set<DNSName> tlsas, cnames, noncnames, glue, checkglue;
  set<string> recordcontents;
  map<string, unsigned int> ttl;

  ostringstream content;
  pair<map<string, unsigned int>::iterator,bool> ret;

  vector<DNSResourceRecord> records;
  if(!suppliedrecords) {
    sd.db->list(zone, sd.domain_id, g_verbose);
    while(sd.db->get(rr)) {
      records.push_back(rr);
    }
  }
  else 
    records=*suppliedrecords;

  for(auto rr : records) { // we modify this
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
            cout<<"[Warning] Parsed and original record content are not equal: "<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<< " '" << rr.content<<"' (Content parsed as '"<<tmp<<"')"<<endl;
            numwarnings++;
          }
        }
      } else {
        struct in6_addr tmpbuf;
        if (inet_pton(AF_INET6, rr.content.c_str(), &tmpbuf) != 1 || rr.content.find('.') != string::npos) {
          cout<<"[Warning] Following record is not a valid IPv6 address: "<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<< " '" << rr.content<<"'"<<endl;
          numwarnings++;
        }
      }
    }
    catch(std::exception& e)
    {
      cout<<"[Error] Following record had a problem: "<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      cout<<"[Error] Error was: "<<e.what()<<endl;
      numerrors++;
      continue;
    }

    if(!rr.qname.isPartOf(zone)) {
      cout<<"[Error] Record '"<<rr.qname.toString()<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone.toString()<<"' is out-of-zone."<<endl;
      numerrors++;
      continue;
    }

    content.str("");
    content<<rr.qname.toString()<<" "<<rr.qtype.getName()<<" "<<rr.content;
    if (recordcontents.count(toLower(content.str()))) {
      cout<<"[Error] Duplicate record found in rrset: '"<<rr.qname.toString()<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"'"<<endl;
      numerrors++;
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
      cout<<"[Error] TTL mismatch in rrset: '"<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<<" "<<rr.content<<"' ("<<ret.first->second<<" != "<<rr.ttl<<")"<<endl;
      numerrors++;
      continue;
    }

    if (isSecure && isOptOut && (rr.qname.countLabels() && rr.qname.getRawLabels()[0] == "*")) {
      cout<<"[Warning] wildcard record '"<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<<" "<<rr.content<<"' is insecure"<<endl;
      cout<<"[Info] Wildcard records in opt-out zones are insecure. Disable the opt-out flag for this zone to avoid this warning. Command: pdnsutil set-nsec3 "<<zone.toString()<<endl;
      numwarnings++;
    }

    if(rr.qname==zone) {
      if (rr.qtype.getCode() == QType::NS) {
        hasNsAtApex=true;
      } else if (rr.qtype.getCode() == QType::DS) {
        cout<<"[Warning] DS at apex in zone '"<<zone.toString()<<"', should not be here."<<endl;
        numwarnings++;
      }
    } else {
      if (rr.qtype.getCode() == QType::SOA) {
        cout<<"[Error] SOA record not at apex '"<<rr.qname.toString()<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone.toString()<<"'"<<endl;
        numerrors++;
        continue;
      } else if (rr.qtype.getCode() == QType::DNSKEY) {
        cout<<"[Warning] DNSKEY record not at apex '"<<rr.qname.toString()<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone.toString()<<"', should not be here."<<endl;
        numwarnings++;
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
        cout<<"[Error] Duplicate CNAME found at '"<<rr.qname.toString()<<"'"<<endl;
        numerrors++;
        continue;
      }
    } else {
      if (rr.qtype.getCode() == QType::RRSIG) {
        if(!presigned) {
          cout<<"[Error] RRSIG found at '"<<rr.qname.toString()<<"' in non-presigned zone. These do not belong in the database."<<endl;
          numerrors++;
          continue;
        }
      } else
        noncnames.insert(rr.qname);
    }

    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3)
    {
      cout<<"[Error] NSEC or NSEC3 found at '"<<rr.qname.toString()<<"'. These do not belong in the database."<<endl;
      numerrors++;
      continue;
    }

    if(!presigned && rr.qtype.getCode() == QType::DNSKEY)
    {
      if(directdnskey)
      {
        if(rr.ttl != sd.default_ttl)
        {
          cout<<"[Warning] DNSKEY TTL of "<<rr.ttl<<" at '"<<rr.qname.toString()<<"' differs from SOA minimum of "<<sd.default_ttl<<endl;
          numwarnings++;
        }
      }
      else
      {
        cout<<"[Warning] DNSKEY at '"<<rr.qname.toString()<<"' in non-presigned zone will mostly be ignored and can cause problems."<<endl;
        numwarnings++;
      }
    }

    // if (rr.qname[rr.qname.size()-1] == '.') {
    //   cout<<"[Error] Record '"<<rr.qname.toString()<<"' has a trailing dot. PowerDNS will ignore this record!"<<endl;
    //   numerrors++;
    // }

    if ( (rr.qtype.getCode() == QType::NS || rr.qtype.getCode() == QType::SRV || rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::CNAME || rr.qtype.getCode() == QType::DNAME) &&
         rr.content[rr.content.size()-1] == '.') {
      cout<<"[Warning] The record "<<rr.qname.toString()<<" with type "<<rr.qtype.getName()<<" has a trailing dot in the content ("<<rr.content<<"). Your backend might not work well with this."<<endl;
      numwarnings++;
    }

    if(rr.auth == 0 && rr.qtype.getCode()!=QType::NS && rr.qtype.getCode()!=QType::A && rr.qtype.getCode()!=QType::AAAA)
    {
      cout<<"[Error] Following record is auth=0, run pdnsutil rectify-zone?: "<<rr.qname.toString()<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      numerrors++;
    }
  }

  for(auto &i: cnames) {
    if (noncnames.find(i) != noncnames.end()) {
      cout<<"[Error] CNAME "<<i.toString()<<" found, but other records with same label exist."<<endl;
      numerrors++;
    }
  }

  for(const auto &i: tlsas) {
    DNSName name = DNSName(i);
    name.trimToLabels(name.getRawLabels().size()-2);
    if (cnames.find(name) == cnames.end() && noncnames.find(name) == noncnames.end()) {
      // No specific record for the name in the TLSA record exists, this
      // is already worth emitting a warning. Let's see if a wildcard exist.
      cout<<"[Warning] ";
      DNSName wcname(name);
      wcname.chopOff();
      wcname.prependRawLabel("*");
      if (cnames.find(wcname) != cnames.end() || noncnames.find(wcname) != noncnames.end()) {
        cout<<"A wildcard record exist for '"<<wcname.toString()<<"' and a TLSA record for '"<<i.toString()<<"'.";
      } else {
        cout<<"No record for '"<<name.toString()<<"' exists, but a TLSA record for '"<<i.toString()<<"' does.";
      }
      numwarnings++;
      cout<<" A query for '"<<name.toString()<<"' will yield an empty response. This is most likely a mistake, please create records for '"<<name.toString()<<"'."<<endl;
    }
  }

  if(!hasNsAtApex) {
    cout<<"[Error] No NS record at zone apex in zone '"<<zone.toString()<<"'"<<endl;
    numerrors++;
  }

  for(const auto &qname : checkglue) {
    if (!glue.count(qname)) {
      cout<<"[Warning] Missing glue for '"<<qname.toString()<<"' in zone '"<<zone.toString()<<"'"<<endl;
      numwarnings++;
    }
  }

  cout<<"Checked "<<numrecords<<" records of '"<<zone.toString()<<"', "<<numerrors<<" errors, "<<numwarnings<<" warnings."<<endl;
  if(!numerrors)
    return 0;
  return 1;
}
