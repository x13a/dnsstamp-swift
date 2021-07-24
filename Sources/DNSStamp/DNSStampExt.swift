public protocol DNSStampProtocol {
    func encode() -> String
    static func decode(_ decoder: DNSStamp.Decoder) -> Result<Self, DNSStamp.Error>
}

extension DNSStamp.PlainDNS:      DNSStampProtocol {}
extension DNSStamp.DNSCrypt:      DNSStampProtocol {}
extension DNSStamp.DoH:           DNSStampProtocol {}
extension DNSStamp.DoT:           DNSStampProtocol {}
extension DNSStamp.DoQ:           DNSStampProtocol {}
extension DNSStamp.ODoHTarget:    DNSStampProtocol {}
extension DNSStamp.DNSCryptRelay: DNSStampProtocol {}
extension DNSStamp.ODoHRelay:     DNSStampProtocol {}
