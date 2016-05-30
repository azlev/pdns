#include <boost/assign/std/vector.hpp>

#include "dnsseckeeper.hh"
#include "ueberbackend.hh"


class CheckZone {
  public:
    
    enum Type {WARNING, ERROR, NUMRECORDS};

    static vector<pair<Type,string>> checkDelegation(const DNSName& zone, UeberBackend &B);

    static vector<pair<Type,string>> checkZone(DNSSECKeeper &dk, SOAData sd, const DNSName& zone, const vector<DNSResourceRecord>* records, bool directdnskey);
};
