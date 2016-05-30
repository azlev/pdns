#include <boost/assign/std/vector.hpp>

#include "dnsseckeeper.hh"
#include "ueberbackend.hh"


class CheckZone {
  public:

    static vector<pair<string,string>> checkZone(DNSSECKeeper &dk, UeberBackend &B, const DNSName& zone, const vector<DNSResourceRecord>* suppliedrecords, bool g_verbose, bool directdnskey);

    static vector<pair<string,string>> checkDelegation(const DNSName& zone, UeberBackend &B);
};
