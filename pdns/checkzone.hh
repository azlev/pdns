#include "dnsseckeeper.hh"
#include "ueberbackend.hh"


class CheckZone {
    public:

        static int checkZone(DNSSECKeeper &dk, UeberBackend &B, const DNSName& zone, const vector<DNSResourceRecord>* suppliedrecords, bool g_verbose, bool directdnskey);
};

