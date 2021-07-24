    import XCTest
    @testable import DNSStamp

    final class DNSStampTests: XCTestCase {
        
        func _testDNSStamp(_ str: String) throws {
            let stamp = try DNSStamp.from(str).get()
            switch stamp {
            case .plainDns(let val): assert(str == val.encode())
            case .dnsCrypt(let val): assert(str == val.encode())
            case .doh(let val): assert(str == val.encode())
            case .dot(let val): assert(str == val.encode())
            case .doq(let val): assert(str == val.encode())
            case .odohTarget(let val): assert(str == val.encode())
            case .dnsCryptRelay(let val): assert(str == val.encode())
            case .odohRelay(let val): assert(str == val.encode())
            }
        }
        
        func testPlainDNS() throws {
            try _testDNSStamp("sdns://AAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd")
        }
        
        func testPlainDNSWithOptions() throws {
            try _testDNSStamp("sdns://AAcAAAAAAAAACTEyNy4wLjAuMQ")
        }
        
        func testDNSCrypt() throws {
            try _testDNSStamp("sdns://AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0")
        }
        
        func testDNSCryptPy() throws {
            try _testDNSStamp("sdns://AQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdIMtq3Fwp-VUQC2W_EpT-VoRXmrNJnMl5jwDQG7XBqaLHGzIuZG5zY3J5cHQtY2VydC5leGFtcGxlLmNvbQ")
        }
        
        func testDNSCryptWithOptions() throws {
            try _testDNSStamp("sdns://AQUAAAAAAAAACTEyNy4wLjAuMSDLatxcKflVEAtlvxKU_laEV5qzSZzJeY8A0Bu1wamixxsyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS5jb20")
        }
        
        func testDoHNoHashes() throws {
            try _testDNSStamp("sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5")
        }
        
        func testDoH22() throws {
            try _testDNSStamp("sdns://AgYAAAAAAAAACDkuOS45LjEwABJkbnM5LnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ")
        }
        
        func testDoH() throws {
            try _testDNSStamp("sdns://AgAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvaC5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5")
        }
        
        func testDoHWithOptions() throws {
            try _testDNSStamp("sdns://AgYAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testDoHWithMultipleHashes() throws {
            try _testDNSStamp("sdns://AgAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testDoHWithBootstrapIps() throws {
            try _testDNSStamp("sdns://AgAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb2guZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x")
        }
        
        func testDoHWithoutHashes() throws {
            try _testDNSStamp("sdns://AgUAAAAAAAAAAAAPZG9oLmV4YW1wbGUuY29tCi9kbnMtcXVlcnk")
        }
        
        func testDoT() throws {
            try _testDNSStamp("sdns://AwAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvdC5leGFtcGxlLmNvbQ")
        }
        
        func testDoTWithOptions() throws {
            try _testDNSStamp("sdns://AwEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20")
        }
        
        func testDoTWithMultipleHashes() throws {
            try _testDNSStamp("sdns://AwAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3QuZXhhbXBsZS5jb20")
        }
        
        func testDoTWithBootstrapIps() throws {
            try _testDNSStamp("sdns://AwAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3QuZXhhbXBsZS5jb20HMS4xLjEuMQ")
        }
        
        func testDoTWithoutHashes() throws {
            try _testDNSStamp("sdns://AwUAAAAAAAAAAAAPZG90LmV4YW1wbGUuY29t")
        }
        
        func testDoQ() throws {
            try _testDNSStamp("sdns://BAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4D2RvcS5leGFtcGxlLmNvbQ")
        }
        
        func testDoQWithOptions() throws {
            try _testDNSStamp("sdns://BAEAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20")
        }
        
        func testDoQWithMultipleHashes() throws {
            try _testDNSStamp("sdns://BAAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1g9kb3EuZXhhbXBsZS5jb20")
        }
        
        func testDoQWithBootstrapIps() throws {
            try _testDNSStamp("sdns://BAAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OA9kb3EuZXhhbXBsZS5jb20HMS4xLjEuMQ")
        }
        
        func testDoQWithoutHashes() throws {
            try _testDNSStamp("sdns://BAUAAAAAAAAAAAAPZG9xLmV4YW1wbGUuY29t")
        }
        
        func testODoHTarget() throws {
            try _testDNSStamp("sdns://BQcAAAAAAAAAEG9kb2guZXhhbXBsZS5jb20HL3RhcmdldA")
        }
        
        func testODoHTargetPy() throws {
            try _testDNSStamp("sdns://BQAAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testODoHTargetWithOptions() throws {
            try _testDNSStamp("sdns://BQYAAAAAAAAAFmRvaC10YXJnZXQuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testDNSCryptRelay() throws {
            try _testDNSStamp("sdns://gQ0xMjcuMC4wLjE6NDQz")
        }
        
        func testODoHRelay() throws {
            try _testDNSStamp("sdns://hQcAAAAAAAAAB1s6OjFdOjGCq80CASMPZG9oLmV4YW1wbGUuY29tBi9yZWxheQ")
        }
        
        func testODoHRelayPy() throws {
            try _testDNSStamp("sdns://hQAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhdID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4FWRvaC1yZWxheS5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5")
        }
        
        func testODoHRelayWithOptions() throws {
            try _testDNSStamp("sdns://hQIAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testODoHRelayWithMultipleHashes() throws {
            try _testDNSStamp("sdns://hQAAAAAAAAAACTEyNy4wLjAuMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCDQskN3amwQ5EhbNOo-OzoGPzCJdw4Ep4yAh7fEnU-Y1hVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ")
        }
        
        func testODoHRelayWithBootstrapIps() throws {
            try _testDNSStamp("sdns://hQAAAAAAAAAACTEyNy4wLjAuMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBVkb2gtcmVsYXkuZXhhbXBsZS5jb20KL2Rucy1xdWVyeQcxLjEuMS4x")
        }
        
        func testODoHRelayWithoutHashes() throws {
            try _testDNSStamp("sdns://hQIAAAAAAAAAAAAVZG9oLXJlbGF5LmV4YW1wbGUuY29tCi9kbnMtcXVlcnk")
        }
    }
