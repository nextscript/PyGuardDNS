"""Diagnose-Skript: zeigt exakt warum DNSSEC-Validierung fuer eine Domain fehlschlaegt."""
import socket
import sys
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.flags
import dns.rcode

from dnssec_validator import DNSSECValidator, DNSSECLookupFailure

UPSTREAM = "1.1.1.1"
UPSTREAM_PORT = 53
TIMEOUT = 5.0


def upstream_query(wire):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(wire, (UPSTREAM, UPSTREAM_PORT))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def diagnose(domain):
    print(f"=== DNSSEC Diagnose fuer {domain} ===\n")
    qname = dns.name.from_text(domain)

    # 1) Upstream-Antwort holen (mit DO+CD)
    print(f"[1] Frage {UPSTREAM} nach {domain} A (DO+CD) ...")
    qmsg = dns.message.make_query(qname, "A", want_dnssec=True)
    qmsg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
    qmsg.flags |= dns.flags.CD
    try:
        resp_wire = upstream_query(qmsg.to_wire())
        rmsg = dns.message.from_wire(resp_wire)
    except Exception as e:
        print(f"    FEHLER: {e}")
        return
    rcode = dns.rcode.to_text(rmsg.rcode())
    ad = bool(rmsg.flags & dns.flags.AD)
    print(f"    rcode={rcode}  AD={ad}  answer={len(rmsg.answer)} rrsets  authority={len(rmsg.authority)} rrsets")

    has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG
        for section in (rmsg.answer, rmsg.authority)
        for rrset in section
    )
    print(f"    RRSIG in Antwort: {has_rrsig}")

    for rrset in rmsg.answer:
        print(f"    answer: {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} ({len(rrset)} records)")
    for rrset in rmsg.authority:
        print(f"    authority: {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} ({len(rrset)} records)")

    # 2) Kettenvalidierung Schritt fuer Schritt
    print(f"\n[2] Ketten-Validierung ...")
    validator = DNSSECValidator(query_func=upstream_query, timeout=10.0)
    ok, err = validator.reload_trust_anchor()
    print(f"    Trust Anchor geladen: {ok}  {err}")

    if has_rrsig:
        # Finde signer
        for rrset in rmsg.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                for rdata in rrset:
                    print(f"    RRSIG signer: {rdata.signer}  covers: {dns.rdatatype.to_text(rdata.type_covered)}  algorithm: {rdata.algorithm}")

        # Versuche zone keys zu holen fuer die Zone
        zone_chain = validator._zone_chain(qname)
        print(f"    Zone-Kette: {[z.to_text() for z in zone_chain]}")

        for zone in zone_chain:
            print(f"\n    --- Zone: {zone.to_text()} ---")
            try:
                dnskey, dnskey_rrsig, _ = validator._fetch_rrset(zone, dns.rdatatype.DNSKEY)
                print(f"    DNSKEY: {'OK (' + str(len(dnskey)) + ' keys)' if dnskey else 'FEHLT'}")
                print(f"    DNSKEY RRSIG: {'OK' if dnskey_rrsig else 'FEHLT'}")
            except Exception as e:
                print(f"    DNSKEY fetch Fehler: {e}")

            if zone != dns.name.root:
                try:
                    ds, ds_rrsig, _ = validator._fetch_rrset(zone, dns.rdatatype.DS)
                    print(f"    DS: {'OK (' + str(len(ds)) + ' records)' if ds else 'FEHLT (insecure delegation)'}")
                    print(f"    DS RRSIG: {'OK' if ds_rrsig else 'FEHLT'}")
                except Exception as e:
                    print(f"    DS fetch Fehler: {e}")

    # 3) Vollstaendige Validierung
    print(f"\n[3] validate_response() ...")
    # Frische Query ohne CD fuer die eigentliche Validierung
    qmsg2 = dns.message.make_query(qname, "A", want_dnssec=True)
    qmsg2.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
    validator._cache.clear()
    result = validator.validate_response(qmsg2, rmsg)
    print(f"    Status:  {result.status}")
    print(f"    Reason:  {result.reason}")
    print(f"    AD:      {result.ad_flag_allowed}")
    if result.validated_rrsets:
        print(f"    Validated: {result.validated_rrsets}")


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "proton.me"
    diagnose(domain)
