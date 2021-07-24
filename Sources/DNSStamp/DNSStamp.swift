import Foundation
import Swift

// https://dnscrypt.info/stamps-specifications

public struct DNSStamp {
    
    public static let prefix    = "sdns://"
    public static let vlenMagic = 0x80
    public typealias ProtoType  = UInt8
    
    public struct Props: OptionSet {
        public let rawValue: UInt64
        
        public init(rawValue: Self.RawValue) {
            self.rawValue = rawValue
        }
        
        public static let dnsSec   = Props(rawValue: 1 << 0)
        public static let noLog    = Props(rawValue: 1 << 1)
        public static let noFilter = Props(rawValue: 1 << 2)
    }
    
    public struct PlainDNS {
        public static let proto: ProtoType = 0x00
        
        public var props: Props
        public var addr: String
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 25)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                try decoder.checkEnd()
                return .success(Self(props: props, addr: addr))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct DNSCrypt {
        public static let proto: ProtoType = 0x01
        
        public var props: Props
        public var addr: String
        public var pk: Data
        public var providerName: String
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 80)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            encoder.lpData(pk)
            encoder.lpString(providerName)
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                let pk = try decoder.lpData()
                guard pk.count == 32 else {
                    return .failure(.unsupportedPk)
                }
                let providerName = try decoder.lpString()
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    addr: addr,
                    pk: pk,
                    providerName: providerName
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct DoH {
        public static let proto: ProtoType = 0x02
        
        public var props: Props
        public var addr: String
        public var hashes: [Data]
        public var hostname: String
        public var path: String
        public var bootstrapIps: [String]?
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 120)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            encoder.vlpData(hashes)
            encoder.lpString(hostname)
            encoder.lpString(path)
            if let ips = bootstrapIps {
                encoder.vlpString(ips)
            }
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                let hashes = try decoder.vlpData()
                let hostname = try decoder.lpString()
                let path = try decoder.lpString()
                var bootstrapIps: [String]? = nil
                if decoder.hasData() {
                    bootstrapIps = try decoder.vlpString()
                }
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    addr: addr,
                    hashes: hashes,
                    hostname: hostname,
                    path: path,
                    bootstrapIps: bootstrapIps
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct DoT {
        public static let proto: ProtoType = 0x03
        
        public var props: Props
        public var addr: String
        public var hashes: [Data]
        public var hostname: String
        public var bootstrapIps: [String]?
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 120)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            encoder.vlpData(hashes)
            encoder.lpString(hostname)
            if let ips = bootstrapIps {
                encoder.vlpString(ips)
            }
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                let hashes = try decoder.vlpData()
                let hostname = try decoder.lpString()
                var bootstrapIps: [String]? = nil
                if decoder.hasData() {
                    bootstrapIps = try decoder.vlpString()
                }
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    addr: addr,
                    hashes: hashes,
                    hostname: hostname,
                    bootstrapIps: bootstrapIps
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct DoQ {
        public static let proto: ProtoType = 0x04
        
        public var props: Props
        public var addr: String
        public var hashes: [Data]
        public var hostname: String
        public var bootstrapIps: [String]?
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 120)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            encoder.vlpData(hashes)
            encoder.lpString(hostname)
            if let ips = bootstrapIps {
                encoder.vlpString(ips)
            }
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                let hashes = try decoder.vlpData()
                let hostname = try decoder.lpString()
                var bootstrapIps: [String]? = nil
                if decoder.hasData() {
                    bootstrapIps = try decoder.vlpString()
                }
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    addr: addr,
                    hashes: hashes,
                    hostname: hostname,
                    bootstrapIps: bootstrapIps
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct ODoHTarget {
        public static let proto: ProtoType = 0x05
        
        public var props: Props
        public var hostname: String
        public var path: String
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 80)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(hostname)
            encoder.lpString(path)
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let hostname = try decoder.lpString()
                let path = try decoder.lpString()
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    hostname: hostname,
                    path: path
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct DNSCryptRelay {
        public static let proto: ProtoType = 0x81
        
        public var addr: String
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 17)
            encoder.proto(Self.proto)
            encoder.lpString(addr)
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let addr = try decoder.lpString()
                try decoder.checkEnd()
                return .success(Self(addr: addr))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public struct ODoHRelay {
        public static let proto: ProtoType = 0x85
        
        public var props: Props
        public var addr: String
        public var hashes: [Data]
        public var hostname: String
        public var path: String
        public var bootstrapIps: [String]?
        
        public func encode() -> String {
            let encoder = Encoder(capacity: 120)
            encoder.proto(Self.proto)
            encoder.props(props)
            encoder.lpString(addr)
            encoder.vlpData(hashes)
            encoder.lpString(hostname)
            encoder.lpString(path)
            if let ips = bootstrapIps {
                encoder.vlpString(ips)
            }
            return encoder.encode()
        }
        
        public static func decode(_ decoder: Decoder) -> Result<Self, Error> {
            do {
                let props = try decoder.props()
                let addr = try decoder.lpString()
                let hashes = try decoder.vlpData()
                let hostname = try decoder.lpString()
                let path = try decoder.lpString()
                var bootstrapIps: [String]? = nil
                if decoder.hasData() {
                    bootstrapIps = try decoder.vlpString()
                }
                try decoder.checkEnd()
                return .success(Self(
                    props: props,
                    addr: addr,
                    hashes: hashes,
                    hostname: hostname,
                    path: path,
                    bootstrapIps: bootstrapIps
                ))
            } catch {
                return .failure(.decoder(error))
            }
        }
    }
    
    public enum Value {
        case plainDns(PlainDNS)
        case dnsCrypt(DNSCrypt)
        case doh(DoH)
        case dot(DoT)
        case doq(DoQ)
        case odohTarget(ODoHTarget)
        case dnsCryptRelay(DNSCryptRelay)
        case odohRelay(ODoHRelay)
    }
    
    public enum Error: Swift.Error {
        case invalidPrefix
        case tooShort
        case base64
        case invalidProto
        case invalidEncoding
        case garbageAfterEnd
        case unsupportedPk
        case decoder(Swift.Error)
    }
    
    public static func from(_ str: String) -> Result<Value, Error> {
        guard str.hasPrefix(prefix) else {
            return .failure(.invalidPrefix)
        }
        let str = str.dropFirst(prefix.count)
        guard let data = base64decode(String(str)) else {
            return .failure(.base64)
        }
        let decoder = Decoder(data)
        let proto: ProtoType
        do {
            proto = try decoder.proto()
        } catch {
            return .failure(.decoder(error))
        }
        switch proto {
        case PlainDNS.proto:
            switch PlainDNS.decode(decoder) {
            case .success(let val): return .success(.plainDns(val))
            case .failure(let err): return .failure(err)
            }
        case DNSCrypt.proto:
            switch DNSCrypt.decode(decoder) {
            case .success(let val): return .success(.dnsCrypt(val))
            case .failure(let err): return .failure(err)
            }
        case DoH.proto:
            switch DoH.decode(decoder) {
            case .success(let val): return .success(.doh(val))
            case .failure(let err): return .failure(err)
            }
        case DoT.proto:
            switch DoT.decode(decoder) {
            case .success(let val): return .success(.dot(val))
            case .failure(let err): return .failure(err)
            }
        case DoQ.proto:
            switch DoQ.decode(decoder) {
            case .success(let val): return .success(.doq(val))
            case .failure(let err): return .failure(err)
            }
        case ODoHTarget.proto:
            switch ODoHTarget.decode(decoder) {
            case .success(let val): return .success(.odohTarget(val))
            case .failure(let err): return .failure(err)
            }
        case DNSCryptRelay.proto:
            switch DNSCryptRelay.decode(decoder) {
            case .success(let val): return .success(.dnsCryptRelay(val))
            case .failure(let err): return .failure(err)
            }
        case ODoHRelay.proto:
            switch ODoHRelay.decode(decoder) {
            case .success(let val): return .success(.odohRelay(val))
            case .failure(let err): return .failure(err)
            }
        default: return .failure(.invalidProto)
        }
    }
    
    public class Encoder {
        public var data: Data
        
        public init(capacity: Int) {
            self.data = Data(capacity: capacity)[...]
        }
        
        public func proto(_ value: ProtoType) {
            data.append(UInt8(value))
        }
        
        public func props(_ value: Props) {
            data.append(contentsOf: withUnsafeBytes(
                of: value.rawValue.littleEndian,
                Array.init
            ))
        }
        
        public func lpData(_ value: Data) {
            data.append(UInt8(value.count))
            data.append(contentsOf: value)
        }
        
        public func lpString(_ value: String) {
            lpData(Data(value.utf8))
        }
        
        public func vlpData(_ values: [Data]) {
            let last = values.count - 1
            if last < 0 {
                data.append(0)
                return
            }
            for (idx, value) in values.enumerated() {
                var vlen = value.count
                if idx < last {
                    vlen |= vlenMagic
                }
                data.append(UInt8(vlen))
                data.append(contentsOf: value)
            }
        }
        
        public func vlpString(_ values: [String]) {
            vlpData(values.map { Data($0.utf8) })
        }
        
        public func encode() -> String {
            let base64 = base64encode(data)
            return "\(prefix)\(base64)"
        }
    }
    
    public class Decoder {
        public var data: Data
        
        public init(_ data: Data) {
            self.data = data[...]
        }
        
        public func proto() throws -> ProtoType {
            return ProtoType(try first())
        }
        
        public func props() throws -> DNSStamp.Props {
            let size = MemoryLayout<Props.RawValue>.size
            guard data.count >= size else {
                throw Error.tooShort
            }
            let raw = data
                .prefix(size)
                .reversed()
                .reduce(0, { $0 << 8 | Props.RawValue($1) })
            data = data.dropFirst(size)
            return DNSStamp.Props(rawValue: raw)
        }
        
        public func lpData() throws -> Data {
            let len = Int(try first())
            guard data.count >= len else {
                throw Error.tooShort
            }
            let result = data.prefix(len)
            data = data.dropFirst(len)
            return result
        }
        
        public func lpString() throws -> String {
            let raw = try lpData()
            guard let result = String(bytes: raw, encoding: .utf8) else {
                throw Error.invalidEncoding
            }
            return result
        }
        
        public func vlpData() throws -> [Data] {
            var results: [Data] = []
            while true {
                let vlen = Int(try first())
                let length = vlen & ~vlenMagic
                guard data.count >= length else {
                    throw Error.tooShort
                }
                if length > 0 {
                    results.append(data.prefix(length))
                    data = data.dropFirst(length)
                }
                if vlen & vlenMagic != vlenMagic {
                    break
                }
            }
            return results
        }
        
        public func vlpString() throws -> [String] {
            let raw = try vlpData()
            var results = [String](repeating: "", count: raw.count)
            for (idx, value) in raw.enumerated() {
                guard let str = String(bytes: value, encoding: .utf8) else {
                    throw Error.invalidEncoding
                }
                results[idx] = str
            }
            return results
        }
        
        public func first() throws -> UInt8 {
            guard !data.isEmpty else {
                throw Error.tooShort
            }
            let result = UInt8(littleEndian: data.first!)
            data = data.dropFirst()
            return result
        }
        
        public func hasData() -> Bool {
            return !data.isEmpty
        }
        
        public func checkEnd() throws {
            guard data.isEmpty else {
                throw Error.garbageAfterEnd
            }
        }
    }
}
