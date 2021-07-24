# dnsstamp-swift

[DNSStamps](https://dnscrypt.info/stamps-specifications/) implementation in swift.

## Example

```swift
import DNSStamp

func main() throws {
    let str = "sdns://AAAAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd"
    
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

main()
```
