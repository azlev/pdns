/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include <boost/algorithm/string.hpp>

/* FIRST PART */
class MemoryBackend : public DNSBackend
{
public:
  MemoryBackend(const string &suffix="")
  {
    setArgPrefix("memory"+suffix);
  }

  bool list(const DNSName &target, int id, bool include_disabled) {
    return false; // we don't support AXFR
  }

  void lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
  {
    d_answer="";
  }

  bool get(DNSResourceRecord &rr)
  {
    return false;
  }

private:
  string d_answer;
  DNSName d_domain;
};

/* SECOND PART */

class MemoryFactory : public BackendFactory
{
public:
  MemoryFactory() : BackendFactory("memory") {}
  void declareArguments(const string &suffix="") {}
  DNSBackend *make(const string &suffix="")
  {
    return new MemoryBackend(suffix);
  }
};

/* THIRD PART */

class MemoryLoader
{
public:
  MemoryLoader()
  {
    BackendMakers().report(new MemoryFactory);
    L << Logger::Info << "[memorybackend] This is the memory backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }  
};

static MemoryLoader memoryLoader;
